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

int bpf_prog_test_run(int prog_fd, int repeat, void *data, __u32 size,
		      void *data_out, __u32 *size_out, __u32 *retval,
		      __u32 *duration)
{
	union bpf_attr attr;
	int ret;

	memset(&attr, 0, sizeof(attr));
	attr.test.prog_fd = prog_fd;
	attr.test.data_in = ptr_to_u64(data);
	attr.test.data_out = ptr_to_u64(data_out);
	attr.test.data_size_in = size;
	attr.test.repeat = repeat;

	ret = SYSCALL_BPF(BPF_PROG_TEST_RUN);
	if (size_out)
		*size_out = attr.test.data_size_out;
	if (retval)
		*retval = attr.test.retval;
	if (duration)
		*duration = attr.test.duration;
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
	var retval C.uint
	var size_out C.uint

	ret := C.bpf_prog_test_run(C.int(p.ProgFD), C.int(p.Repeat),
		unsafe.Pointer(&p.InData[0]), C.__u32(len(p.InData)),
		unsafe.Pointer(&p.OutData[0]), &size_out,
		&retval, &dur)
	if ret == -1 {
		return fmt.Errorf("bpf_prog_test_run() failed\n")
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
