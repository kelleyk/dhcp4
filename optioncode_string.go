// Code generated by "stringer -type=OptionCode"; DO NOT EDIT

package dhcp4

import "fmt"

const _OptionCode_name = "End"

var _OptionCode_index = [...]uint8{0, 3}

func (i OptionCode) String() string {
	i -= 255
	if i >= OptionCode(len(_OptionCode_index)-1) {
		return fmt.Sprintf("OptionCode(%d)", i+255)
	}
	return _OptionCode_name[_OptionCode_index[i]:_OptionCode_index[i+1]]
}
