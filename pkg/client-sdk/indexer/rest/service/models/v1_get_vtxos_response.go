// Code generated by go-swagger; DO NOT EDIT.

package models

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"context"
	"strconv"

	"github.com/go-openapi/errors"
	"github.com/go-openapi/strfmt"
	"github.com/go-openapi/swag"
)

// V1GetVtxosResponse v1 get vtxos response
//
// swagger:model v1GetVtxosResponse
type V1GetVtxosResponse struct {

	// page
	Page *V1IndexerPageResponse `json:"page,omitempty"`

	// vtxos
	Vtxos []*V1IndexerVtxo `json:"vtxos"`
}

// Validate validates this v1 get vtxos response
func (m *V1GetVtxosResponse) Validate(formats strfmt.Registry) error {
	var res []error

	if err := m.validatePage(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateVtxos(formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

func (m *V1GetVtxosResponse) validatePage(formats strfmt.Registry) error {
	if swag.IsZero(m.Page) { // not required
		return nil
	}

	if m.Page != nil {
		if err := m.Page.Validate(formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("page")
			} else if ce, ok := err.(*errors.CompositeError); ok {
				return ce.ValidateName("page")
			}
			return err
		}
	}

	return nil
}

func (m *V1GetVtxosResponse) validateVtxos(formats strfmt.Registry) error {
	if swag.IsZero(m.Vtxos) { // not required
		return nil
	}

	for i := 0; i < len(m.Vtxos); i++ {
		if swag.IsZero(m.Vtxos[i]) { // not required
			continue
		}

		if m.Vtxos[i] != nil {
			if err := m.Vtxos[i].Validate(formats); err != nil {
				if ve, ok := err.(*errors.Validation); ok {
					return ve.ValidateName("vtxos" + "." + strconv.Itoa(i))
				} else if ce, ok := err.(*errors.CompositeError); ok {
					return ce.ValidateName("vtxos" + "." + strconv.Itoa(i))
				}
				return err
			}
		}

	}

	return nil
}

// ContextValidate validate this v1 get vtxos response based on the context it is used
func (m *V1GetVtxosResponse) ContextValidate(ctx context.Context, formats strfmt.Registry) error {
	var res []error

	if err := m.contextValidatePage(ctx, formats); err != nil {
		res = append(res, err)
	}

	if err := m.contextValidateVtxos(ctx, formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

func (m *V1GetVtxosResponse) contextValidatePage(ctx context.Context, formats strfmt.Registry) error {

	if m.Page != nil {

		if swag.IsZero(m.Page) { // not required
			return nil
		}

		if err := m.Page.ContextValidate(ctx, formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("page")
			} else if ce, ok := err.(*errors.CompositeError); ok {
				return ce.ValidateName("page")
			}
			return err
		}
	}

	return nil
}

func (m *V1GetVtxosResponse) contextValidateVtxos(ctx context.Context, formats strfmt.Registry) error {

	for i := 0; i < len(m.Vtxos); i++ {

		if m.Vtxos[i] != nil {

			if swag.IsZero(m.Vtxos[i]) { // not required
				return nil
			}

			if err := m.Vtxos[i].ContextValidate(ctx, formats); err != nil {
				if ve, ok := err.(*errors.Validation); ok {
					return ve.ValidateName("vtxos" + "." + strconv.Itoa(i))
				} else if ce, ok := err.(*errors.CompositeError); ok {
					return ce.ValidateName("vtxos" + "." + strconv.Itoa(i))
				}
				return err
			}
		}

	}

	return nil
}

// MarshalBinary interface implementation
func (m *V1GetVtxosResponse) MarshalBinary() ([]byte, error) {
	if m == nil {
		return nil, nil
	}
	return swag.WriteJSON(m)
}

// UnmarshalBinary interface implementation
func (m *V1GetVtxosResponse) UnmarshalBinary(b []byte) error {
	var res V1GetVtxosResponse
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*m = res
	return nil
}
