// Copyright (c) 2020 Dropbox, Inc.
// Full license can be found in the LICENSE file.

package goebpf

/*
#include <errno.h>
#include <unistd.h>
#include <stdlib.h>

#include "bpf.h"
#include "bpf_helpers.h"

// Mac has syscall() deprecated and this produces some noise during package install.
// Wrap all syscalls into macro.
#ifdef __linux__
#define SYSCALL_BPF(command)		\
	syscall(__NR_bpf, command, &attr, sizeof(attr));
#else
#define SYSCALL_BPF(command)		0
#endif

// struct used to run the test
// https://elixir.bootlin.com/linux/latest/source/tools/lib/bpf/bpf.h#L192
struct bpf_prog_test_run_attr {
	int prog_fd;
	int repeat;
	const void *data_in;
	__u32 data_size_in;
	void *data_out;
	__u32 data_size_out;
	__u32 retval;
	__u32 duration;
	const void *ctx_in;
	__u32 ctx_size_in;
	void *ctx_out;
	__u32 ctx_size_out;
};

int bpf_prog_test_run_xattr(struct bpf_prog_test_run_attr *test_attr)
{
	union bpf_attr attr;
	int ret;

	if (!test_attr->data_out && test_attr->data_size_out > 0)
		return -EINVAL;

	memset(&attr, 0, sizeof(attr));
	attr.test.prog_fd = test_attr->prog_fd;
	attr.test.data_in = ptr_to_u64(test_attr->data_in);
	attr.test.data_out = ptr_to_u64(test_attr->data_out);
	attr.test.data_size_in = test_attr->data_size_in;
	attr.test.data_size_out = test_attr->data_size_out;
	attr.test.ctx_in = ptr_to_u64(test_attr->ctx_in);
	attr.test.ctx_out = ptr_to_u64(test_attr->ctx_out);
	attr.test.ctx_size_in = test_attr->ctx_size_in;
	attr.test.ctx_size_out = test_attr->ctx_size_out;
	attr.test.repeat = test_attr->repeat;

	ret = SYSCALL_BPF(BPF_PROG_TEST_RUN);
	test_attr->data_size_out = attr.test.data_size_out;
	test_attr->ctx_size_out = attr.test.ctx_size_out;
	test_attr->retval = attr.test.retval;
	test_attr->duration = attr.test.duration;
	return ret;
}

int ebpf_prog_test_run(int prog_fd, int repeat, void *data,
		      void *data_out, __u32 *size_out, __u32 *retval,
			  __u32 *duration)
{
	int ret;

	struct bpf_prog_test_run_attr test_attr = {
			.prog_fd	= prog_fd,
			.repeat 	= repeat,
			.data_in	= data,
			.data_out	= data_out,
	};
	ret = bpf_prog_test_run_xattr(&test_attr);
	*size_out = test_attr.data_size_out;
	*retval = test_attr.retval;
	*duration = test_attr.duration;
	return ret;

};

*/
import "C"

import (
	"fmt"
	"unsafe"
)

type ProgTest struct {
	ProgFD   int
	Repeat   int
	InData   []byte
	OutData  []byte
	Retval   int
	Duration int
}

// docstring
func (p *ProgTest) progTestRun() error {
	var dur C.uint
	defer C.free(unsafe.Pointer(&dur))
	var retval C.uint
	defer C.free(unsafe.Pointer(&retval))
	var size_out C.uint
	defer C.free(unsafe.Pointer(&size_out))

	ret := C.ebpf_prog_test_run(C.int(p.ProgFD), C.int(p.Repeat),
		unsafe.Pointer(&p.InData[0]),
		unsafe.Pointer(&p.OutData[0]), &size_out,
		&retval, &dur)
	if ret == -1 {
		return fmt.Errorf("ebpf_prog_test_run() failed\n")
	}
	p.Retval = int(retval)
	p.Duration = int(dur)

	return nil
}

func (p *ProgTest) RunTest() error {
	err := p.progTestRun()
	if err != nil {
		return err
	}
	return nil
}

func NewTest(prog Program, repeat int) *ProgTest {
	return &ProgTest{ProgFD: prog.GetFd(), Repeat: repeat}
}
