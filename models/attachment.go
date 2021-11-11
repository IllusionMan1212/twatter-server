package models

import (
	"github.com/jackc/pgtype"
)

type Attachment struct {
	Url   string `json:"url"`
	Type  string `json:"type"`
	Color string `json:"bg_color"`
}

type DBAttachment struct {
	Urls   pgtype.VarcharArray `json:"url"`
	Types  pgtype.VarcharArray `json:"type"`
	Colors pgtype.VarcharArray `json:"bg_color"`
}

type SocketAttachment struct {
	Mimetype string `json:"mimetype"`
	Data     string `json:"data"`
}

const (
	Large     = "large"
	Medium    = "medium"
	Small     = "small"
	Thumbnail = "thumbnail"
)

var SupportedAttachmentTypes = map[string]bool{"image": true, "gif": true, "video": true}
