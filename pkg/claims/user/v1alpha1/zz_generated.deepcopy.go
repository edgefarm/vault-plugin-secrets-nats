//go:build !ignore_autogenerated
// +build !ignore_autogenerated

/*
Copyright 2023 The EdgeFarm Authors.

Licensed under the Mozilla Public License, version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    https://www.mozilla.org/en-US/MPL/2.0/

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

// Code generated by controller-gen. DO NOT EDIT.

package v1alpha1

import ()

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *Limits) DeepCopyInto(out *Limits) {
	*out = *in
	in.UserLimits.DeepCopyInto(&out.UserLimits)
	out.NatsLimits = in.NatsLimits
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new Limits.
func (in *Limits) DeepCopy() *Limits {
	if in == nil {
		return nil
	}
	out := new(Limits)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *TimeRange) DeepCopyInto(out *TimeRange) {
	*out = *in
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new TimeRange.
func (in *TimeRange) DeepCopy() *TimeRange {
	if in == nil {
		return nil
	}
	out := new(TimeRange)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *User) DeepCopyInto(out *User) {
	*out = *in
	in.UserPermissionLimits.DeepCopyInto(&out.UserPermissionLimits)
	in.GenericFields.DeepCopyInto(&out.GenericFields)
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new User.
func (in *User) DeepCopy() *User {
	if in == nil {
		return nil
	}
	out := new(User)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *UserClaims) DeepCopyInto(out *UserClaims) {
	*out = *in
	out.ClaimsData = in.ClaimsData
	in.User.DeepCopyInto(&out.User)
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new UserClaims.
func (in *UserClaims) DeepCopy() *UserClaims {
	if in == nil {
		return nil
	}
	out := new(UserClaims)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *UserLimits) DeepCopyInto(out *UserLimits) {
	*out = *in
	if in.Src != nil {
		in, out := &in.Src, &out.Src
		*out = make([]string, len(*in))
		copy(*out, *in)
	}
	if in.Times != nil {
		in, out := &in.Times, &out.Times
		*out = make([]TimeRange, len(*in))
		copy(*out, *in)
	}
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new UserLimits.
func (in *UserLimits) DeepCopy() *UserLimits {
	if in == nil {
		return nil
	}
	out := new(UserLimits)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *UserPermissionLimits) DeepCopyInto(out *UserPermissionLimits) {
	*out = *in
	in.Permissions.DeepCopyInto(&out.Permissions)
	in.Limits.DeepCopyInto(&out.Limits)
	if in.AllowedConnectionTypes != nil {
		in, out := &in.AllowedConnectionTypes, &out.AllowedConnectionTypes
		*out = make([]string, len(*in))
		copy(*out, *in)
	}
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new UserPermissionLimits.
func (in *UserPermissionLimits) DeepCopy() *UserPermissionLimits {
	if in == nil {
		return nil
	}
	out := new(UserPermissionLimits)
	in.DeepCopyInto(out)
	return out
}