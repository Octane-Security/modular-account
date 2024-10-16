// This file is part of Modular Account.
//
// Copyright 2024 Alchemy Insights, Inc.
//
// SPDX-License-Identifier: GPL-3.0-or-later
//
// This program is free software: you can redistribute it and/or modify it under the terms of the GNU General
// Public License as published by the Free Software Foundation, either version 3 of the License, or (at your
// option) any later version.
//
// This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the
// implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for
// more details.
//
// You should have received a copy of the GNU General Public License along with this program. If not, see
// <https://www.gnu.org/licenses/>.

pragma solidity ^0.8.26;

import {Call} from "@erc6900/reference-implementation/interfaces/IModularAccount.sol";

// Mock contract for inspecting the ABI decoding logic of a parameter of type `Call[]`.
// To view the generated bytecode, run `forge inspect test/mocks/MockDecoder.sol:MockDecoder ir`,
// optionally adding `| pbcopy` to copy it to the clipboard.
// Note that when put as a parameter to an external function, the "data end" the compiler will check against during
// decoding will be inferred as `calldatasize()`, but for our purposes, we must substitute that with a different
// value that is less than the total calldata size.
contract MockDecoder {
    event Log(bytes data) anonymous;

    function inspect(Call[] calldata calls) external {
        for (uint256 i = 0; i < calls.length; i++) {
            emit Log(abi.encodePacked(calls[i].target));

            emit Log(abi.encodePacked(calls[i].value));

            emit Log(abi.encodePacked(calls[i].data));
        }
    }
}

// Notable functions to inspect:

// ---- Decoding the outer Call[] array. ----

// function abi_decode_t_array$_t_struct$_Call_$75_calldata_ptr_$dyn_calldata_ptr(offset, end) -> arrayPos, length
// {
//     if iszero(slt(add(offset, 0x1f), end)) {
//          revert_error_1b9f4a0a5773e33b91aa01db23bf8c55fce1411167c872835e7fa00a4f17d46d()
//     }
//     length := calldataload(offset)
//     if gt(length, 0xffffffffffffffff) {
//          revert_error_15abf5612cd996bc235ba1e55a4a30ac60e6bb601ff7ba4ad3f179b6be8d0490()
//     }
//     arrayPos := add(offset, 0x20)
//     if gt(add(arrayPos, mul(length, 0x20)), end) {
//          revert_error_81385d8c0b31fffe14be1da910c8bd3a80be4cfa248e04f42ec0faea3132a8ef()
//     }
// }
//
// function abi_decode_tuple_t_array$_t_struct$_Call_$75_calldata_ptr_$dyn_calldata_ptr(headStart, dataEnd) ->
// value0, value1 {
//     if slt(sub(dataEnd, headStart), 32) {
//          revert_error_dbdddcbe895c83990c08b3492a0e83918d802a52331272ac6fdb6a7c4aea3b1b()
//     }
//
//     {
//
//         let offset := calldataload(add(headStart, 0))
//         if gt(offset, 0xffffffffffffffff) {
//              revert_error_c1322bf8034eace5e0b5c7295db60986aa89aae5e0ea0873e4689e076861a5db()
//         }
//
//         value0, value1 := abi_decode_t_array$_t_struct$_Call_$75_calldata_ptr_$dyn_calldata_ptr(add(headStart,
//                              offset), dataEnd)
//     }
// }

// ---- Decoding a variable of type `Call calldata`, while iterating through the array. ----

// function access_calldata_tail_t_struct$_Call_$75_calldata_ptr(base_ref, ptr_to_tail) -> addr {
//     let rel_offset_of_tail := calldataload(ptr_to_tail)
//     if iszero(slt(rel_offset_of_tail, sub(sub(calldatasize(), base_ref), sub(0x60, 1)))) {
//          revert_error_356d538aaf70fba12156cc466564b792649f8f3befb07b071c91142253e175ad()
//     }
//     addr := add(base_ref, rel_offset_of_tail)
//
// }
//
// function calldata_array_index_access_t_array$_t_struct$_Call_$75_calldata_ptr_$dyn_calldata_ptr(base_ref,
// length, index) -> addr {
//     if iszero(lt(index, length)) { panic_error_0x32() }
//     addr := add(base_ref, mul(index, 32))
//
//     addr := access_calldata_tail_t_struct$_Call_$75_calldata_ptr(base_ref, addr)
//
// }

// ---- Safely reading the `target` value. ----

// function cleanup_t_uint160(value) -> cleaned {
//     cleaned := and(value, 0xffffffffffffffffffffffffffffffffffffffff)
// }
//
// function cleanup_t_address(value) -> cleaned {
//     cleaned := cleanup_t_uint160(value)
// }
//
// function validator_revert_t_address(value) {
//     if iszero(eq(value, cleanup_t_address(value))) { revert(0, 0) }
// }
//
// function read_from_calldatat_address(ptr) -> returnValue {
//
//     let value := calldataload(ptr)
//     validator_revert_t_address(value)
//
//     returnValue :=
//
//     value
//
// }

// ---- Safely reading from the `data` field of a Call struct. ----

// function access_calldata_tail_t_bytes_calldata_ptr(base_ref, ptr_to_tail) -> addr, length {
//     let rel_offset_of_tail := calldataload(ptr_to_tail)
//     if iszero(slt(rel_offset_of_tail, sub(sub(calldatasize(), base_ref), sub(0x20, 1)))) {
//          revert_error_356d538aaf70fba12156cc466564b792649f8f3befb07b071c91142253e175ad()
//     }
//     addr := add(base_ref, rel_offset_of_tail)
//
//     length := calldataload(addr)
//     if gt(length, 0xffffffffffffffff) {
//          revert_error_1e55d03107e9c4f1b5e21c76a16fba166a461117ab153bcce65e6a4ea8e5fc8a()
//     }
//     addr := add(addr, 32)
//     if sgt(addr, sub(calldatasize(), mul(length, 0x01))) {
//          revert_error_977805620ff29572292dee35f70b0f3f3f73d3fdd0e9f4d7a901c2e43ab18a2e()
//     }
//
// }