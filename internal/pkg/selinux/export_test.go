// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package selinux

// SetLabelFunc replaces the label setter for tests.
func SetLabelFunc(fn func(path, label string, excludeLabels ...string) error) {
	setLabel = fn
}
