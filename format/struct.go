package format

import "reflect"

func StructToMap(data interface{}) map[string]interface{} {
	result := make(map[string]interface{})

	types := reflect.TypeOf(data)
	values := reflect.ValueOf(data)

	if types.Kind() == reflect.Ptr || types.Kind() == reflect.Interface {
		types = types.Elem()
		values = values.Elem()
	}

	// looping data in struct
	for i := 0; i < types.NumField(); i++ {
		value := values.Field(i)
		field := types.Field(i)

		// ignore if value can be using interface
		if !value.CanInterface() {
			continue
		}

		// get tag json from field
		jsonKey := field.Tag.Get("json")

		// ignore if jsonkey empty string or "-"
		if jsonKey == "" || jsonKey == "-" {
			continue
		}

		result[jsonKey] = value.Interface()
	}

	return result
}
