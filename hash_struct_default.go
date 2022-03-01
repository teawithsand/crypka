package crypka

import (
	"io"
	"reflect"
)

type DefaultStructHashWriter struct {
}

func (dsh *DefaultStructHashWriter) WriteStruct(ctx HashContext, res interface{}, w io.Writer) (err error) {
	inner := innerDefaultStructHasher{
		ctx: ctx,
		helper: &HashableHelper{
			W: w,
		},
		fieldsCache: nil,
	}

	err = inner.enterData(reflect.ValueOf(res))
	if err != nil {
		return
	}
	return
}

type innerDefaultStructHasher struct {
	ctx    HashContext
	helper *HashableHelper

	fieldsCache map[reflect.Type]taggedFields
}

func (dsh *innerDefaultStructHasher) enterData(data reflect.Value) (err error) {
	hnew, ok := data.Interface().(HashableNew)
	if ok {
		err = hnew.HashSelf(dsh.helper)
		return
	}

	// for other types use walking with reflection

	reflectData := reflect.ValueOf(data)
	for reflectData.Kind() == reflect.Ptr {
		// skip nil pointers
		//  and pointers to pointer to nil
		if reflectData.IsNil() {
			return
		}
		reflectData = reflectData.Elem()
	}

	switch reflectData.Kind() {
	case reflect.Slice:
		len := reflectData.Elem().Len()
		err = dsh.helper.EnterSlice(len)
		if err != nil {
			return
		}

		for i := 0; i < len; i++ {
			err = dsh.enterData(reflectData.Index(i))
			if err != nil {
				return
			}
		}

		err = dsh.helper.ExitSlice()
		if err != nil {
			return
		}
	case reflect.Array:
		// note: this makes resizing array backwards-incompatible
		len := reflectData.Elem().Len()
		for i := 0; i < len; i++ {
			err = dsh.enterData(reflectData.Index(i))
			if err != nil {
				return
			}
		}

	case reflect.Uint8:
		err = dsh.helper.WriteUint8(reflectData.Interface().(uint8))
		if err != nil {
			return
		}
	case reflect.Uint16:
		err = dsh.helper.WriteUint16(reflectData.Interface().(uint16))
		if err != nil {
			return
		}
	case reflect.Uint32:
		err = dsh.helper.WriteUint32(reflectData.Interface().(uint32))
		if err != nil {
			return
		}
	case reflect.Uint64:
		err = dsh.helper.WriteUint64(reflectData.Interface().(uint64))
		if err != nil {
			return
		}
	case reflect.Int8:
		err = dsh.helper.WriteInt8(reflectData.Interface().(int8))
		if err != nil {
			return
		}
	case reflect.Int16:
		err = dsh.helper.WriteInt16(reflectData.Interface().(int16))
		if err != nil {
			return
		}
	case reflect.Int32:
		err = dsh.helper.WriteInt32(reflectData.Interface().(int32))
		if err != nil {
			return
		}
	case reflect.Int64:
		err = dsh.helper.WriteInt64(reflectData.Interface().(int64))
		if err != nil {
			return
		}
	case reflect.Float32:
		// since floats are quirky, for instance NaN value may be more than one NaN but comparing NaNs
		// is a mess and some serializers support the only NaN, so it's not
		// https://en.wikipedia.org/wiki/NaN (quiet nan/signaling nan)
		//
		// and in general floats are mess when comes to comparing them
		// so I won't implement them.
		// especially because some FP numbers can be encoded in more than one binary representation
		fallthrough
	case reflect.Struct:
		fields, cachedFieldsOk := dsh.fieldsCache[reflectData.Type()]

		if !cachedFieldsOk {
			if dsh.fieldsCache == nil {
				dsh.fieldsCache = make(map[reflect.Type]taggedFields)
			}

			_, fields, err = computeTaggedFields(reflectData)
			if err != nil {
				return
			}

			dsh.fieldsCache[reflectData.Type()] = fields
		}

		err = dsh.helper.EnterStruct()
		if err != nil {
			return
		}

		length := reflectData.NumField()

		if len(fields) == 0 {
			for i := 0; i < length; i++ {
				fieldValue := reflectData.Field(i)
				err = dsh.enterData(fieldValue)
				if err != nil {
					return
				}
			}
		} else {
			for _, f := range fields {
				err = dsh.enterData(reflectData.Field(f.index))
				if err != nil {
					return
				}
			}
		}

		err = dsh.helper.ExitStruct()
		if err != nil {
			return
		}

	case reflect.Float64:
		fallthrough
	case reflect.Map:
		// since order of keys is undefined, and making slice and sorting them is a mess to do with reflection
		fallthrough
	default:
		err = ErrHashNotSupported
		return
	}

	return
}
