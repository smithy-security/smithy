// Code generated by MockGen. DO NOT EDIT.
// Source: internal/reporter/reporter.go
//
// Generated by this command:
//
//	mockgen -package reporter_test -source internal/reporter/reporter.go -destination internal/reporter/reporter_mock_test.go MessageSender
//

// Package reporter_test is a generated GoMock package.
package reporter_test

import (
	context "context"
	reflect "reflect"

	gomock "go.uber.org/mock/gomock"
)

// MockMessageSender is a mock of MessageSender interface.
type MockMessageSender struct {
	ctrl     *gomock.Controller
	recorder *MockMessageSenderMockRecorder
	isgomock struct{}
}

// MockMessageSenderMockRecorder is the mock recorder for MockMessageSender.
type MockMessageSenderMockRecorder struct {
	mock *MockMessageSender
}

// NewMockMessageSender creates a new mock instance.
func NewMockMessageSender(ctrl *gomock.Controller) *MockMessageSender {
	mock := &MockMessageSender{ctrl: ctrl}
	mock.recorder = &MockMessageSenderMockRecorder{mock}
	return mock
}

// EXPECT returns an object that allows the caller to indicate expected use.
func (m *MockMessageSender) EXPECT() *MockMessageSenderMockRecorder {
	return m.recorder
}

// Close mocks base method.
func (m *MockMessageSender) Close() error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "Close")
	ret0, _ := ret[0].(error)
	return ret0
}

// Close indicates an expected call of Close.
func (mr *MockMessageSenderMockRecorder) Close() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Close", reflect.TypeOf((*MockMessageSender)(nil).Close))
}

// CreateThread mocks base method.
func (m *MockMessageSender) CreateThread(ctx context.Context, msg string) (string, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "CreateThread", ctx, msg)
	ret0, _ := ret[0].(string)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// CreateThread indicates an expected call of CreateThread.
func (mr *MockMessageSenderMockRecorder) CreateThread(ctx, msg any) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "CreateThread", reflect.TypeOf((*MockMessageSender)(nil).CreateThread), ctx, msg)
}

// SendMessages mocks base method.
func (m *MockMessageSender) SendMessages(ctx context.Context, threadID string, messages []string) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "SendMessages", ctx, threadID, messages)
	ret0, _ := ret[0].(error)
	return ret0
}

// SendMessages indicates an expected call of SendMessages.
func (mr *MockMessageSenderMockRecorder) SendMessages(ctx, threadID, messages any) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "SendMessages", reflect.TypeOf((*MockMessageSender)(nil).SendMessages), ctx, threadID, messages)
}
