package storage

// EscapeS3KeyForTest re-exports the internal s3-key encoder for the
// external (_test) package's unit tests. Production code uses the
// unexported escapeS3Key directly via CopyObject; this indirection
// keeps that surface internal.
func EscapeS3KeyForTest(key string) string { return escapeS3Key(key) }
