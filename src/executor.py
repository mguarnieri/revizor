"""
File: Executor Interface

Copyright (C) 2021 Oleksii Oleksenko
Copyright (C) 2020 Microsoft Corporation
SPDX-License-Identifier: MIT
"""
import subprocess
import os.path
import csv
import numpy as np
from subprocess import run
from collections import Counter
from typing import List
from interfaces import CombinedHTrace, HTrace, Input, TestCase, Executor

from helpers import write_to_pseudo_file, write_to_pseudo_file_bytes, assemble_and_link
from config import CONF

PFCReading = int


class X86Intel(Executor):
    previous_num_inputs: int = 0

    def __init__(self):
        super().__init__()
        write_to_pseudo_file(CONF.warmups, '/sys/x86-executor/warmups')
        write_to_pseudo_file("1" if CONF.enable_ssbp_patch else "0",
                             "/sys/x86-executor/enable_ssbp_patch")
        write_to_pseudo_file("1" if CONF.enable_pre_run_flush else "0",
                             "/sys/x86-executor/enable_pre_run_flush")
        write_to_pseudo_file("1" if CONF.enable_assist_page else "0",
                             "/sys/x86-executor/enable_mds")
        write_to_pseudo_file(CONF.attack_variant, "/sys/x86-executor/measurement_mode")

    def load_test_case(self, test_case: TestCase):
        write_to_pseudo_file(test_case.to_binary(), "/sys/x86-executor/code")

    def trace_test_case(self, inputs: List[Input], num_measurements: int = 0) \
            -> List[CombinedHTrace]:
        # make sure it's not a dummy call
        if not inputs:
            return []

        # is kernel module ready?
        if not os.path.isfile("/proc/x86-executor"):
            print("Error: x86 Intel Executor: kernel module not loaded")

        if num_measurements == 0:
            num_measurements = CONF.num_measurements

        # convert the inputs into a byte sequence
        byte_inputs = [i.tobytes() for i in inputs]
        byte_inputs_merged = bytes().join(byte_inputs)

        # protocol of loading inputs (must be in this order):
        # 1) Announce the number of inputs
        write_to_pseudo_file(str(len(inputs)), "/sys/x86-executor/n_inputs")
        # 2) Load the inputs
        write_to_pseudo_file_bytes(byte_inputs_merged, "/sys/x86-executor/inputs")
        # 3) Check that the load was successful
        with open('/sys/x86-executor/n_inputs', 'r') as f:
            if f.readline() == '0\n':
                print("Failure loading inputs!")
                raise Exception()

        traces: List[List] = [[] for _ in inputs]
        pfc_readings: List[List] = [[[], [], []] for _ in inputs]
        for _ in range(num_measurements):
            # measure
            subprocess.run(f"taskset -c {CONF.measurement_cpu} cat /proc/x86-executor "
                           "| sudo tee measurement.txt >/dev/null",
                           shell=True, check=True)

            # fetch the results
            with open('measurement.txt', "r") as f:
                reader = csv.DictReader(f)
                if not reader.fieldnames or 'CACHE_MAP' not in reader.fieldnames:
                    raise Exception("Error: Hardware Trace was not produced.")

                for i, row in enumerate(reader):
                    trace = int(row['CACHE_MAP'])
                    if CONF.ignore_first_cache_line:
                        trace &= 9223372036854775807
                    traces[i].append(trace)

                    pfc_readings[i][0].append(int(row['pfc1']))
                    pfc_readings[i][1].append(int(row['pfc2']))
                    pfc_readings[i][2].append(int(row['pfc3']))

        if num_measurements == 1:
            if self.coverage:
                self.coverage.executor_hook([[r[0][0], r[1][0], r[2][0]] for r in pfc_readings])
            return [t[0] for t in traces]

        # remove outliers and merge
        merged_traces = [0 for _ in inputs]
        for i, trace_list in enumerate(traces):
            num_occurrences: Counter = Counter()
            for trace in trace_list:
                num_occurrences[trace] += 1
                # print(pretty_bitmap(trace))
                if num_occurrences[trace] <= CONF.max_outliers:
                    # if we see too few occurrences of this specific htrace,
                    # it might be noise, ignore it for now
                    continue
                elif num_occurrences[trace] == CONF.max_outliers + 1:
                    # otherwise, merge it
                    merged_traces[i] |= trace

        # same for PFC readings, except select max. values instead of merging
        filtered_pfc_readings = [[0, 0, 0] for _ in inputs]
        for i, reading_lists in enumerate(pfc_readings):
            num_occurrences = Counter()

            for reading in reading_lists[0]:
                num_occurrences[reading] += 1
                if num_occurrences[reading] <= CONF.max_outliers * 2:
                    # if we see too few occurrences of this specific htrace,
                    # it might be noise, ignore it for now
                    continue
                elif num_occurrences[reading] == CONF.max_outliers * 2 + 1:
                    # otherwise, update max
                    filtered_pfc_readings[i][0] = max(filtered_pfc_readings[i][0], reading)

        if self.coverage:
            self.coverage.executor_hook(filtered_pfc_readings)

        return merged_traces

    def read_base_addresses(self):
        with open('/sys/x86-executor/print_sandbox_base', 'r') as f:
            sandbox_base = f.readline()
        with open('/sys/x86-executor/print_code_base', 'r') as f:
            code_base = f.readline()
        return int(sandbox_base, 16), int(code_base, 16)



class X86Gem5(Executor):
    code_segment: str = ""
    RUNTIME_R_SIZE: int = 1024 * 1024
    CODE_SIZE: int = 4 * 1024
    RSP_OFFSET: int = RUNTIME_R_SIZE // 2
    RBP_OFFSET: int = RUNTIME_R_SIZE // 2
    R14_OFFSET: int  = RUNTIME_R_SIZE // 2
    code_base: int  = 4198400 
    sandbox_base: int = 5251072
    stack_base: int = 7340032
    r14_init = sandbox_base + R14_OFFSET 
    rsp_init = stack_base + RSP_OFFSET
    rbp_init = stack_base + RBP_OFFSET


    def __init__(self):
        self.gem5_location = CONF.gem5_location
        self.gem5_build = CONF.gem5_build
        self.gem5_output_location = CONF.gem5_output_location
        self.gem5_additional_params = CONF.gem5_additional_flags
        self.gem5_flags = CONF.gem5_flags
        self.test_case_path = CONF.gem5_test_case_path
        self.trace_mode = CONF.gem5_trace_mode
        self.batch_size = CONF.gem5_batch_size

    def load_test_case(self, test_case: TestCase):
        self.code_segment = test_case.to_string()

    def construct_program(self, code_segment: str = "", init_registers: str = "", init_flags: str = "",data_segment: str = "", stack_segment = "") -> str:

        def clean_up(code_segment: str) -> str:
            code_segment = code_segment.replace(".intel_syntax noprefix", "")
            code_segment = code_segment.replace(".test_case_enter:", "")
            code_segment = code_segment.replace(".test_case_main:","")
            code_segment = code_segment.replace(".test_case_main.entry:","")
            code_segment = code_segment.replace(".test_case_main.exit:","")
            code_segment = code_segment.replace(".test_case_exit:","")
            code_segment = code_segment.replace(".test_case_main.exit",".exit")
            return code_segment

        program = ".intel_syntax noprefix\n"
        program += ".globl _start\n"
        # program += ".globl main\n"
        program += ".section .text\n"
        program += "_start:\n"
        # program += "main:\n"
        program += init_flags
        program += init_registers
        program += clean_up(code_segment)
        program += ".exit:\n"  #exit routine
        program += "    LFENCE\n"
        program += "    MOV     RAX, 60\n" # system call 60 is exit
        program += "    XOR     RDI, RDI\n" # we want return code 0
        program += "    SYSCALL\n" # invoke operating system to exit
        program += ".section .data\n"
        program += data_segment
        program += "\n"
        program += ".section .stack\n"
        program += stack_segment
        program += "\n"
        return program

    def generate_test_data(self, input_: Input) -> (str, str, str, str):

        # Values in memory
        values = []
        for i in input_:
            values.append(f"0x{bytes.hex(i.tobytes())}")
        data_segment = "   .QUAD {}\n".format(','.join(values))

        # Values in registers and flags
        init_registers = ""
        init_flags = ""
        registers = ["RAX", "RBX", "RCX", "RDX", "RSI", "RDI", "EFLAGS"]
        for i, value in enumerate(input_.get_registers()):
            if registers[i] != "EFLAGS":
                init_registers += f"  MOV {registers[i]}, {value}\n"
            else: 
                ## initialize flags
                value = (value & np.uint64(2263)) | np.uint64(2)
                init_flags += "  MOV RAX, {}\n".format(value)    # store eflags in eax
                init_flags += "  PUSH RAX\n"   # push eax onto stack
                init_flags += "  POPF\n"       # POP top of stack (eax in this case) into eflags
        # initialize to 0 all the other registers
        others = ["R8", "R9", "R10", "R11", "R12", "R13", "R15"]
        for reg in others:
            init_registers += f"  MOV {reg}, 0\n"

        # Init stack
        stack_values = []
        for i in range(0, self.RUNTIME_R_SIZE , 64):
            stack_values.append(  '0x%0*X' % (16,0)  )
        stack_segment = "    .QUAD {}\n".format(','.join(stack_values)) 

        return init_registers, data_segment, init_flags, stack_segment


    def get_trace(self, index: int) -> CombinedHTrace:

        def read_trace(file_name, fields):
            encoded_trace_path = "{loc}/{name}.gz".format(loc=self.gem5_output_location,name=file_name)
            decoded_trace_path = "{loc}/{name}.txt".format(loc=self.gem5_output_location,name=file_name)
            run(["{loc}/util/decode_packet_trace.py".format(loc=self.gem5_location), encoded_trace_path, decoded_trace_path], capture_output = True)
            with open(decoded_trace_path, "r") as f:
                csv_reader = csv.reader(f, delimiter=',')
                values = []
                for row in csv_reader:
                    values.append( [row[x] for x in fields] )
                return values
            return []

        if self.trace_mode == "data_cache":
            values = read_trace("dCacheTrace_{}".format(index), [1,2])
        elif self.trace_mode == "instr_cache":
            values = read_trace("iCacheTrace_{}".format(index), [1,2])
        elif self.trace_mode == "all_caches":
            dCache_values = read_trace("dCacheTrace_{}".format(index), [1,2,5])
            iCache_values = read_trace("iCacheTrace_{}".format(index), [1,2,5])
            merged_values = sorted(dCache_values + iCache_values,  key=lambda x: x[2])
            values = [ [x[0], x[1]] for x in merged_values ]
        elif self.trace_mode == "pipeline":
            print("Unsupported trace mode {}".format(self.trace_mode))
            exit(1)
        else:
            print("Unsupported trace mode {}".format(self.trace_mode))
            exit(1)      

        # TODO not the most elegant way of getting an hash :-\ 
        return hash(str(values)) 

    def trace_test_case(self, inputs: List[Input], num_measurements: int = 0) -> List[CombinedHTrace]:

        if self.code_segment == "":
            print("Error: no test case")
            exit(1)

        traces = []

        def chunks(lst, n):
            """Yield successive n-sized chunks from lst."""
            for i in range(0, len(lst), n):
                yield lst[i:i + n]

        ctr =0
        for input_chunk in chunks(inputs,self.batch_size):
            
            # prepare all binaries
            counter = 0
            processes = []
            for input_ in input_chunk:

                ctr = ctr+1
                test_case_path = f"{self.test_case_path}_{counter}"

                # 1. generate test data from input seed
                (init_registers, data_segment, init_flags, stack_segment) = self.generate_test_data(input_)

                # 2. construct the assembly program 
                program = self.construct_program(self.code_segment, init_registers, init_flags, data_segment, stack_segment)

                # 3. create the binary
                with open(test_case_path+".asm", "w") as f:
                    f.write(program)
                assemble_and_link(test_case_path+".asm", test_case_path+".o", test_case_path+".out")

                processes.append(test_case_path+".out")
                counter = counter + 1

            # 4. run gem5 
            cmd = []
            cmd.append("{loc}/{build}".format(loc=self.gem5_location, build=self.gem5_build))
            # cmd.append("--debug-flags=SyscallBase") 
            # cmd.append("--debug-flags=ExecAll")
            # cmd.append("--debug-flags=DRAM")
            cmd.append("--outdir={}".format(self.gem5_output_location))
            cmd.append("{loc}/configs/example/se.py".format(loc=self.gem5_location))
            cmd.append("-c")
            cmd.append(';'.join(processes))
            for fl in self.gem5_flags:
                cmd.append(fl)
            for fl in self.gem5_additional_params:
                cmd.append(fl)
            cmd.append("--num-cpu={}".format(len(processes)))
            run(cmd, capture_output=True)

            # 5. collect traces
            for i in range(0,len(processes)):
                traces.append(self.get_trace(i))  

            # 6. cleanup
            run(["rm", "-rf",  self.gem5_output_location])
            for i in range(0,len(processes)):
                test_case_path = "{tc}_{ctr}".format(tc=self.test_case_path, ctr=i)
                run(["rm", "{tc}.out".format(tc=test_case_path),  "{tc}.o".format(tc=test_case_path), "{tc}.asm".format(tc=test_case_path)]) 
           
        return traces
        

    def read_base_addresses(self):
        return self.sandbox_base, self.stack_base, self.code_base




def get_executor() -> Executor:
    options = {
        'x86-intel': X86Intel,
        'x86-gem5' : X86Gem5
    }
    if CONF.executor not in options:
        print("Error: unknown executor in config.py")
        exit(1)
    return options[CONF.executor]()
