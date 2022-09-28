// Code generated by go-swagger; DO NOT EDIT.

package operation

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"fmt"

	"github.com/go-openapi/runtime"
	"github.com/go-openapi/strfmt"
)

// New creates a new operation API client.
func New(transport runtime.ClientTransport, formats strfmt.Registry) ClientService {
	return &Client{transport: transport, formats: formats}
}

/*
Client for operation API
*/
type Client struct {
	transport runtime.ClientTransport
	formats   strfmt.Registry
}

// ClientService is the interface for Client methods
type ClientService interface {
	Cacerts(params *CacertsParams) (*CacertsOK, error)

	CacertsLabelled(params *CacertsLabelledParams) (*CacertsLabelledOK, error)

	Simpleenroll(params *SimpleenrollParams, authInfo runtime.ClientAuthInfoWriter) (*SimpleenrollOK, error)

	SimpleenrollLabelled(params *SimpleenrollLabelledParams, authInfo runtime.ClientAuthInfoWriter) (*SimpleenrollLabelledOK, error)

	Simplereenroll(params *SimplereenrollParams, authInfo runtime.ClientAuthInfoWriter) (*SimplereenrollOK, error)

	SimplereenrollLabelled(params *SimplereenrollLabelledParams, authInfo runtime.ClientAuthInfoWriter) (*SimplereenrollLabelledOK, error)

	SetTransport(transport runtime.ClientTransport)
}

/*
  Cacerts distributions of c a certificates
*/
func (a *Client) Cacerts(params *CacertsParams) (*CacertsOK, error) {
	// TODO: Validate the params before sending
	if params == nil {
		params = NewCacertsParams()
	}

	result, err := a.transport.Submit(&runtime.ClientOperation{
		ID:                 "cacerts",
		Method:             "GET",
		PathPattern:        "/cacerts",
		ProducesMediaTypes: []string{"application/pkcs7-mime"},
		ConsumesMediaTypes: []string{"application/json"},
		Schemes:            []string{"https"},
		Params:             params,
		Reader:             &CacertsReader{formats: a.formats},
		Context:            params.Context,
		Client:             params.HTTPClient,
	})
	if err != nil {
		return nil, err
	}
	success, ok := result.(*CacertsOK)
	if ok {
		return success, nil
	}
	// unexpected success response
	// safeguard: normally, absent a default response, unknown success responses return an error above: so this is a codegen issue
	msg := fmt.Sprintf("unexpected success response for cacerts: API contract not enforced by server. Client expected to get an error, but got: %T", result)
	panic(msg)
}

/*
  CacertsLabelled distributions of c a certificates
*/
func (a *Client) CacertsLabelled(params *CacertsLabelledParams) (*CacertsLabelledOK, error) {
	// TODO: Validate the params before sending
	if params == nil {
		params = NewCacertsLabelledParams()
	}

	result, err := a.transport.Submit(&runtime.ClientOperation{
		ID:                 "cacerts-labelled",
		Method:             "GET",
		PathPattern:        "/{label}/cacerts",
		ProducesMediaTypes: []string{"application/pkcs7-mime"},
		ConsumesMediaTypes: []string{"application/json"},
		Schemes:            []string{"https"},
		Params:             params,
		Reader:             &CacertsLabelledReader{formats: a.formats},
		Context:            params.Context,
		Client:             params.HTTPClient,
	})
	if err != nil {
		return nil, err
	}
	success, ok := result.(*CacertsLabelledOK)
	if ok {
		return success, nil
	}
	// unexpected success response
	// safeguard: normally, absent a default response, unknown success responses return an error above: so this is a codegen issue
	msg := fmt.Sprintf("unexpected success response for cacerts-labelled: API contract not enforced by server. Client expected to get an error, but got: %T", result)
	panic(msg)
}

/*
  Simpleenroll enrollments of clients
*/
func (a *Client) Simpleenroll(params *SimpleenrollParams, authInfo runtime.ClientAuthInfoWriter) (*SimpleenrollOK, error) {
	// TODO: Validate the params before sending
	if params == nil {
		params = NewSimpleenrollParams()
	}

	result, err := a.transport.Submit(&runtime.ClientOperation{
		ID:                 "simpleenroll",
		Method:             "POST",
		PathPattern:        "/simpleenroll",
		ProducesMediaTypes: []string{"application/pkcs7-mime"},
		ConsumesMediaTypes: []string{"application/pkcs10"},
		Schemes:            []string{"https"},
		Params:             params,
		Reader:             &SimpleenrollReader{formats: a.formats},
		AuthInfo:           authInfo,
		Context:            params.Context,
		Client:             params.HTTPClient,
	})
	if err != nil {
		return nil, err
	}
	success, ok := result.(*SimpleenrollOK)
	if ok {
		return success, nil
	}
	// unexpected success response
	// safeguard: normally, absent a default response, unknown success responses return an error above: so this is a codegen issue
	msg := fmt.Sprintf("unexpected success response for simpleenroll: API contract not enforced by server. Client expected to get an error, but got: %T", result)
	panic(msg)
}

/*
  SimpleenrollLabelled enrollments of clients
*/
func (a *Client) SimpleenrollLabelled(params *SimpleenrollLabelledParams, authInfo runtime.ClientAuthInfoWriter) (*SimpleenrollLabelledOK, error) {
	// TODO: Validate the params before sending
	if params == nil {
		params = NewSimpleenrollLabelledParams()
	}

	result, err := a.transport.Submit(&runtime.ClientOperation{
		ID:                 "simpleenroll-labelled",
		Method:             "POST",
		PathPattern:        "/{label}/simpleenroll",
		ProducesMediaTypes: []string{"application/pkcs7-mime"},
		ConsumesMediaTypes: []string{"application/pkcs10"},
		Schemes:            []string{"https"},
		Params:             params,
		Reader:             &SimpleenrollLabelledReader{formats: a.formats},
		AuthInfo:           authInfo,
		Context:            params.Context,
		Client:             params.HTTPClient,
	})
	if err != nil {
		return nil, err
	}
	success, ok := result.(*SimpleenrollLabelledOK)
	if ok {
		return success, nil
	}
	// unexpected success response
	// safeguard: normally, absent a default response, unknown success responses return an error above: so this is a codegen issue
	msg := fmt.Sprintf("unexpected success response for simpleenroll-labelled: API contract not enforced by server. Client expected to get an error, but got: %T", result)
	panic(msg)
}

/*
  Simplereenroll enrollments of clients requires mutual tls
*/
func (a *Client) Simplereenroll(params *SimplereenrollParams, authInfo runtime.ClientAuthInfoWriter) (*SimplereenrollOK, error) {
	// TODO: Validate the params before sending
	if params == nil {
		params = NewSimplereenrollParams()
	}

	result, err := a.transport.Submit(&runtime.ClientOperation{
		ID:                 "simplereenroll",
		Method:             "POST",
		PathPattern:        "/simplereenroll",
		ProducesMediaTypes: []string{"application/pkcs7-mime"},
		ConsumesMediaTypes: []string{"application/pkcs10"},
		Schemes:            []string{"https"},
		Params:             params,
		Reader:             &SimplereenrollReader{formats: a.formats},
		AuthInfo:           authInfo,
		Context:            params.Context,
		Client:             params.HTTPClient,
	})
	if err != nil {
		return nil, err
	}
	success, ok := result.(*SimplereenrollOK)
	if ok {
		return success, nil
	}
	// unexpected success response
	// safeguard: normally, absent a default response, unknown success responses return an error above: so this is a codegen issue
	msg := fmt.Sprintf("unexpected success response for simplereenroll: API contract not enforced by server. Client expected to get an error, but got: %T", result)
	panic(msg)
}

/*
  SimplereenrollLabelled enrollments of clients requires mutual tls
*/
func (a *Client) SimplereenrollLabelled(params *SimplereenrollLabelledParams, authInfo runtime.ClientAuthInfoWriter) (*SimplereenrollLabelledOK, error) {
	// TODO: Validate the params before sending
	if params == nil {
		params = NewSimplereenrollLabelledParams()
	}

	result, err := a.transport.Submit(&runtime.ClientOperation{
		ID:                 "simplereenroll-labelled",
		Method:             "POST",
		PathPattern:        "/{label}/simplereenroll",
		ProducesMediaTypes: []string{"application/pkcs7-mime"},
		ConsumesMediaTypes: []string{"application/pkcs10"},
		Schemes:            []string{"https"},
		Params:             params,
		Reader:             &SimplereenrollLabelledReader{formats: a.formats},
		AuthInfo:           authInfo,
		Context:            params.Context,
		Client:             params.HTTPClient,
	})
	if err != nil {
		return nil, err
	}
	success, ok := result.(*SimplereenrollLabelledOK)
	if ok {
		return success, nil
	}
	// unexpected success response
	// safeguard: normally, absent a default response, unknown success responses return an error above: so this is a codegen issue
	msg := fmt.Sprintf("unexpected success response for simplereenroll-labelled: API contract not enforced by server. Client expected to get an error, but got: %T", result)
	panic(msg)
}

// SetTransport changes the transport on the client
func (a *Client) SetTransport(transport runtime.ClientTransport) {
	a.transport = transport
}
