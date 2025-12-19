package model

import "golang.org/x/sys/unix"

const (
	FanotifyEventMetadataSize = 24
)

// FanotifyEventMetadata
/*
type FanotifyEventMetadata struct {
	Event_len    uint32
	Vers         uint8
	Reserved     uint8
	Metadata_len uint16
	Mask         uint64
	Fd           int32
	Pid          int32
}
*/

// FanotifyEventInfoFid 对应 C 结构体 fanotify_event_info_fid 的头部
// 后面紧跟 fsid 和 file_handle
type FanotifyEventInfoFid struct {
	Hdr  FanotifyEventInfoHeader
	Fsid unix.Fsid

	// FileHandle follows here

}

// FanotifyEventInfoHeader 对应 C 结构体 fanotify_event_info_header
type FanotifyEventInfoHeader struct {
	// 信息的类型 (FID? PIDFD? ERROR?)
	InfoType uint8
	// 填充位 (为了内存对齐，通常为0)
	Pad uint8
	// 当前整个 Info 块的总长度 (包括 Header 自己)
	Len uint16
}
type FileHandle struct {
	// Size of FHandle
	HandleBytes uint32

	// Handle type
	HandleType uint32

	// 	FHandle follows here

}

// struct file_handle {
//     unsigned int  handle_bytes;   /* Size of f_handle [in, out] */
// 		int           handle_type;    /* Handle type [out] */
// 		unsigned char f_handle[0];    /* File identifier (sized by caller) [out] */
// };

/*
type FanotifyEventMetadata struct {
	Event_len    uint32
	Vers         uint8
	Reserved     uint8
	Metadata_len uint16
	Mask         uint64
	Fd           int32
	Pid          int32
}
*/
