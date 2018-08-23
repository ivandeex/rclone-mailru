package baidupcs

import "io"

type readerLen64 struct {
	reader io.Reader
	len    int64
}

func (r64 *readerLen64) Read(p []byte) (n int, err error) {
	return r64.reader.Read(p)
}

func (r64 *readerLen64) Len() int64 {
	return r64.len
}

//type readerAtLen64 struct {
//	readerLen64
//}
//
//func (r *readerAtLen64) ReadAt(p []byte, off int64) (n int, err error) {
//	return r.reader.(io.ReaderAt).ReadAt(p, off)
//}
//
//type multiUploadAgent struct {
//	f          *Fs
//	fileSize   int64
//	reader     io.Reader
//	pcsClient  *baidupcs.BaiduPCS
//	targetPath string
//}
//
//func (mua *multiUploadAgent) Precreate() (perr error) {
//	return nil
//}
//
//func (mua *multiUploadAgent) TmpFile(ctx context.Context, partseq int, partOffset int64, readerlen64 rio.ReaderLen64) (checksum string, terr error) {
//	return mua.pcsClient.UploadTmpFile(newFragmentUploadFunc(mua.f, mua.fileSize, readers.NewRepeatableReader(mua.reader)))
//}
//
//func (mua *multiUploadAgent) CreateSuperFile(checksumList ...string) (cerr error) {
//	return mua.pcsClient.UploadCreateSuperFile(mua.targetPath, checksumList...)
//}
