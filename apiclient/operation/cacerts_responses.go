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

// CacertsReader is a Reader for the Cacerts structure.
type CacertsReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *CacertsReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 200:
		result := NewCacertsOK()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	case 500:
		result := NewCacertsInternalServerError()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	default:
		return nil, runtime.NewAPIError("response status code does not match any response statuses defined for this endpoint in the swagger spec", response, response.Code())
	}
}

// NewCacertsOK creates a CacertsOK with default headers values
func NewCacertsOK() *CacertsOK {
	var (
		// initialize headers with default values
		contentTransferEncodingDefault = string("base64")

		contentTypeDefault = string("application/pkcs7-mime")
	)

	return &CacertsOK{

		ContentTransferEncoding: contentTransferEncodingDefault,
		ContentType:             contentTypeDefault,
	}
}

/* CacertsOK describes a response with status code 200, with default header values.

successful operation
*/
type CacertsOK struct {
	ContentTransferEncoding string
	ContentType             string

	Payload string
}

func (o *CacertsOK) Error() string {
	return fmt.Sprintf("[GET /cacerts][%d] cacertsOK  %+v", 200, o.Payload)
}
func (o *CacertsOK) GetPayload() string {
	return o.Payload
}

func (o *CacertsOK) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

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

// NewCacertsInternalServerError creates a CacertsInternalServerError with default headers values
func NewCacertsInternalServerError() *CacertsInternalServerError {
	return &CacertsInternalServerError{}
}

/* CacertsInternalServerError describes a response with status code 500, with default header values.

something went wrong
*/
type CacertsInternalServerError struct {
	Payload string
}

func (o *CacertsInternalServerError) Error() string {
	return fmt.Sprintf("[GET /cacerts][%d] cacertsInternalServerError  %+v", 500, o.Payload)
}
func (o *CacertsInternalServerError) GetPayload() string {
	return o.Payload
}

func (o *CacertsInternalServerError) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	// response payload
	if err := consumer.Consume(response.Body(), &o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}
