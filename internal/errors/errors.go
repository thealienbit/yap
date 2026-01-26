package errors

import "errors"

var (
	ErrInvalidVault     = errors.New("invalid vault")
	ErrAuthFailed       = errors.New("authentication failed")
	ErrRollbackDetected = errors.New("rollback detected")
	ErrCorruptData      = errors.New("corrupt data")
	ErrCryptoFailure    = errors.New("cryptographic failure")
	ErrConfig           = errors.New("configuration error")
)


// return fmt.Errorf("%w: vault_version downgrade", errors.ErrRollbackDetected)
// 
//
//
// if errors.Is(err, errors.ErrRollbackDetected) {
//     // hard stop
// }

