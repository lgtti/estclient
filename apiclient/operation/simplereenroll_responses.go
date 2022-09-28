// Code generated by go-swagger; DO NOT EDIT.

package operation

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"fmt"
	"io"

	"github.com/go-openapi/runtime"
	"github.com/go-openapi/strfmt"
)

// SimplereenrollReader is a Reader for the Simplereenroll structure.
type SimplereenrollReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *SimplereenrollReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 200:
		result := NewSimplereenrollOK()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	case 400:
		result := NewSimplereenrollBadRequest()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 401:
		result := NewSimplereenrollUnauthorized()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 403:
		result := NewSimplereenrollForbidden()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 500:
		result := NewSimplereenrollInternalServerError()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	default:
		return nil, runtime.NewAPIError("response status code does not match any response statuses defined for this endpoint in the swagger spec", response, response.Code())
	}
}

// NewSimplereenrollOK creates a SimplereenrollOK with default headers values
func NewSimplereenrollOK() *SimplereenrollOK {
	var (
		// initialize headers with default values
		contentTransferEncodingDefault = string("base64")

		contentTypeDefault = string("application/pkcs7-mime")
	)

	return &SimplereenrollOK{

		ContentTransferEncoding: contentTransferEncodingDefault,
		ContentType:             contentTypeDefault,
	}
}

/* SimplereenrollOK describes a response with status code 200, with default header values.

successful operation
*/
type SimplereenrollOK struct {
	ContentTransferEncoding string
	ContentType             string

	Payload string
}

func (o *SimplereenrollOK) Error() string {
	return fmt.Sprintf("[POST /simplereenroll][%d] simplereenrollOK  %+v", 200, o.Payload)
}
func (o *SimplereenrollOK) GetPayload() string {
	return o.Payload
}

func (o *SimplereenrollOK) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	// hydrates response header Content-Transfer-Encoding
	hdrContentTransferEncoding := response.GetHeader("Content-Transfer-Encoding")

	if hdrContentTransferEncoding != "" {
		o.ContentTransferEncoding = hdrContentTransferEncoding
	}

	// hydrates response header Content-Type
	hdrContentType := response.GetHeader("Content-Type")

	if hdrContentType != "" {
		o.ContentType = hdrContentType
	}

	// response payload
	if err := consumer.Consume(response.Body(), &o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewSimplereenrollBadRequest creates a SimplereenrollBadRequest with default headers values
func NewSimplereenrollBadRequest() *SimplereenrollBadRequest {
	return &SimplereenrollBadRequest{}
}

/* SimplereenrollBadRequest describes a response with status code 400, with default header values.

invalid request
*/
type SimplereenrollBadRequest struct {
	Payload string
}

func (o *SimplereenrollBadRequest) Error() string {
	return fmt.Sprintf("[POST /simplereenroll][%d] simplereenrollBadRequest  %+v", 400, o.Payload)
}
func (o *SimplereenrollBadRequest) GetPayload() string {
	return o.Payload
}

func (o *SimplereenrollBadRequest) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	// response payload
	if err := consumer.Consume(response.Body(), &o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewSimplereenrollUnauthorized creates a SimplereenrollUnauthorized with default headers values
func NewSimplereenrollUnauthorized() *SimplereenrollUnauthorized {
	return &SimplereenrollUnauthorized{}
}

/* SimplereenrollUnauthorized describes a response with status code 401, with default header values.

Authentication information is missing or invalid
*/
type SimplereenrollUnauthorized struct {
	WWWAuthenticate string
}

func (o *SimplereenrollUnauthorized) Error() string {
	return fmt.Sprintf("[POST /simplereenroll][%d] simplereenrollUnauthorized ", 401)
}

func (o *SimplereenrollUnauthorized) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	// hydrates response header WWW_Authenticate
	hdrWWWAuthenticate := response.GetHeader("WWW_Authenticate")

	if hdrWWWAuthenticate != "" {
		o.WWWAuthenticate = hdrWWWAuthenticate
	}

	return nil
}

// NewSimplereenrollForbidden creates a SimplereenrollForbidden with default headers values
func NewSimplereenrollForbidden() *SimplereenrollForbidden {
	return &SimplereenrollForbidden{}
}

/* SimplereenrollForbidden describes a response with status code 403, with default header values.

client certificates were not presented
*/
type SimplereenrollForbidden struct {
	Payload string
}

func (o *SimplereenrollForbidden) Error() string {
	return fmt.Sprintf("[POST /simplereenroll][%d] simplereenrollForbidden  %+v", 403, o.Payload)
}
func (o *SimplereenrollForbidden) GetPayload() string {
	return o.Payload
}

func (o *SimplereenrollForbidden) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	// response payload
	if err := consumer.Consume(response.Body(), &o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewSimplereenrollInternalServerError creates a SimplereenrollInternalServerError with default headers values
func NewSimplereenrollInternalServerError() *SimplereenrollInternalServerError {
	return &SimplereenrollInternalServerError{}
}

/* SimplereenrollInternalServerError describes a response with status code 500, with default header values.

something went wrong
*/
type SimplereenrollInternalServerError struct {
	Payload string
}

func (o *SimplereenrollInternalServerError) Error() string {
	return fmt.Sprintf("[POST /simplereenroll][%d] simplereenrollInternalServerError  %+v", 500, o.Payload)
}
func (o *SimplereenrollInternalServerError) GetPayload() string {
	return o.Payload
}

func (o *SimplereenrollInternalServerError) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	// response payload
	if err := consumer.Consume(response.Body(), &o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}
