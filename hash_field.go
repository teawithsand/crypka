package crypka

import (
	"reflect"
	"sort"
	"strconv"
)

type taggedField struct {
	index    int
	priority int32
}

type taggedFields []taggedField

func (tf taggedFields) Len() int {
	return len(tf)
}

func (tf taggedFields) Swap(i, j int) {
	tf[i], tf[j] = tf[j], tf[i]
}

func (tf taggedFields) Less(i, j int) bool {
	return tf[i].priority < tf[j].priority
}

// TODO(teawithsand): consider caching return values of this function
//  at least in scope of single hashing
//  that'd be useful for slices

func computeTaggedFields(reflectStruct reflect.Value) (required bool, tf taggedFields, err error) {
	// TODO(teawithsand): prettify implementation to use single for loop

	var hasTags bool
	length := reflectStruct.Type().NumField()
	for i := 0; i < length; i++ {
		f := reflectStruct.Type().Field(i)

		tag := f.Tag.Get(hashTagName)
		if len(tag) > 0 {
			hasTags = true
			break
		}
	}
	if !hasTags {
		required = false
		return
	}

	required = true
	tf = make(taggedFields, 0, length)

	for i := 0; i < length; i++ {
		f := reflectStruct.Type().Field(i)
		tag := f.Tag.Get(hashTagName)

		if tag == "-" {
			continue
		}

		var priority int64
		if len(tag) > 0 {
			priority, err = strconv.ParseInt(tag, 10, 32)
			if err != nil {
				return
			}
		}

		tf = append(tf, taggedField{
			index:    i,
			priority: int32(priority),
		})
	}

	sort.Sort(tf)

	return
}
