/*
Copyright 2018 The Kubernetes Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package admission

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"

	v1 "k8s.io/api/admission/v1"
	"k8s.io/api/admission/v1beta1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/serializer"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
)

var admissionScheme = runtime.NewScheme()
var admissionCodecs = serializer.NewCodecFactory(admissionScheme)

func init() {
	utilruntime.Must(v1.AddToScheme(admissionScheme))
	utilruntime.Must(v1beta1.AddToScheme(admissionScheme))
}

var _ http.Handler = &Webhook{}

func (wh *Webhook) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	var body []byte
	var err error

	// Wrap bad request logging/writing.
	writeBadRequest := func(err error, msg string, logFields ...interface{}) {
		wh.log.Error(err, msg, logFields...)
		wh.writeResponse(w, Errored(http.StatusBadRequest, err))
		return
	}

	if r.Body != nil {
		if body, err = ioutil.ReadAll(r.Body); err != nil {
			writeBadRequest(err, "unable to read the body from the incoming request")
			return
		}
	} else {
		err = errors.New("request body is empty")
		writeBadRequest(err, "bad request")
		return
	}

	// verify the content type is accurate
	contentType := r.Header.Get("Content-Type")
	if contentType != "application/json" {
		err = fmt.Errorf("contentType=%s, expected application/json", contentType)
		writeBadRequest(err, "unable to process a request with an unknown content type", "content type", contentType)
		return
	}

	// Both v1 and v1beta1 AdmissionReview types are the exact same, so the v1beta1 type can
	// be decoded into the v1 type. However the runtime codec's decoder guesses which type to
	// decode into by GVK if an Object's TypeMeta isn't set. By checking TypeMeta for v1beta1
	// and setting API version to v1, the decoder will coerce a v1beta1 AdmissionReview to v1.
	ar := unversionedAdmissionReview{
		Request:  &v1.AdmissionRequest{},
		Response: &v1.AdmissionResponse{},
	}
	if err := json.Unmarshal(body, &ar.TypeMeta); err != nil {
		writeBadRequest(err, "unable to decode the request typemeta")
		return
	}
	switch ar.GroupVersionKind() {
	case v1.SchemeGroupVersion.WithKind("AdmissionReview"):
	case v1beta1.SchemeGroupVersion.WithKind("AdmissionReview"):
		ar.SetGroupVersionKind(v1.SchemeGroupVersion.WithKind("AdmissionReview"))
	default:
		writeBadRequest(errors.New("admission review has bad typemeta"), ar.GroupVersionKind().String())
		return
	}

	if _, _, err := admissionCodecs.UniversalDeserializer().Decode(body, nil, &ar); err != nil {
		writeBadRequest(err, "unable to decode the request")
		return
	}
	req := Request{}
	req.AdmissionRequest = *ar.Request
	wh.log.V(1).Info("received request", "UID", req.UID, "kind", req.Kind, "resource", req.Resource)

	// TODO: add panic-recovery for Handle
	reviewResponse := wh.Handle(r.Context(), req)
	wh.writeResponse(w, reviewResponse)
}

func (wh *Webhook) writeResponse(w io.Writer, response Response) {
	encoder := json.NewEncoder(w)
	responseAdmissionReview := v1.AdmissionReview{
		Response: &response.AdmissionResponse,
	}
	err := encoder.Encode(responseAdmissionReview)
	if err != nil {
		wh.log.Error(err, "unable to encode the response")
		wh.writeResponse(w, Errored(http.StatusInternalServerError, err))
	} else {
		res := responseAdmissionReview.Response
		if log := wh.log; log.V(1).Enabled() {
			if res.Result != nil {
				log = log.WithValues("code", res.Result.Code, "reason", res.Result.Reason)
			}
			log.V(1).Info("wrote response", "UID", res.UID, "allowed", res.Allowed)
		}
	}
}

// unversionedAdmissionReview is used to decode both v1 and v1beta1 AdmissionReview types.
type unversionedAdmissionReview struct {
	metav1.TypeMeta `json:",inline"`
	Request         *v1.AdmissionRequest  `json:"request,omitempty"`
	Response        *v1.AdmissionResponse `json:"response,omitempty"`
}

var _ runtime.Object = &unversionedAdmissionReview{}

func (o unversionedAdmissionReview) DeepCopyObject() runtime.Object {
	ar := v1.AdmissionReview{
		TypeMeta: o.TypeMeta,
		Request:  o.Request,
		Response: o.Response,
	}
	aro := ar.DeepCopyObject().(*v1.AdmissionReview)
	return &unversionedAdmissionReview{
		TypeMeta: aro.TypeMeta,
		Request:  aro.Request,
		Response: aro.Response,
	}
}
