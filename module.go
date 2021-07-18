package keystorev4

import "encoding/json"

type moduleLookahead struct {
	Function string `json:"function"`
}

type moduleRemainder struct {
	Params  interface{} `json:"params"`
	Message JsonBytes   `json:"message"`
}

// unmarshalModule unmarshals the function and message data, and parameters based on paramsFn.
//
// The paramsFn should return a pointer to the destination struct to json-unmarshal into,
// or return an error if the function was not recognized.
func unmarshalModule(data []byte, function *string, message *JsonBytes,
	paramsFn func(function string) (interface{}, error)) error {

	var lookahead moduleLookahead
	if err := json.Unmarshal(data, &lookahead); err != nil {
		return err
	}
	*function = lookahead.Function
	dst, err := paramsFn(lookahead.Function)
	if err != nil {
		return err
	}
	var remainder moduleRemainder
	remainder.Params = dst
	if err := json.Unmarshal(data, &remainder); err != nil {
		return err
	}
	*message = remainder.Message
	return nil
}
