import ida_hexrays as hr
import logging

from ida_hexrays import minsn_t, m_goto, mop_t
from ida_hexrays import mblock_t
from ida_hexrays import mbl_array_t
from ida_hexrays import m_ijmp, m_call, MMAT_CALLS, BLT_1WAY, MBL_GOTO


def insert_goto_instruction(blk: hr.mblock_t, goto_blk_serial: int, nop_previous_instruction=False):
    if blk.tail is not None:
        goto_ins = minsn_t(blk.tail)
    else:
        goto_ins = minsn_t(blk.start)

    if nop_previous_instruction:
        blk.make_nop(blk.tail)
    blk.insert_into_block(goto_ins, blk.tail)

    # We nop instruction before setting it to goto to avoid error 52123
    blk.make_nop(blk.tail)
    goto_ins.opcode = m_goto
    goto_ins.l = mop_t()
    goto_ins.l.make_blkref(goto_blk_serial)



def change_1way_block_successor(blk: mblock_t, blk_successor_serial: int) -> bool:
    if blk.nsucc() != 1:
        return False

    mba: mbl_array_t = blk.mba
    previous_blk_successor_serial = blk.succset[0]
    previous_blk_successor = mba.get_mblock(previous_blk_successor_serial)

    if blk.tail is None:
        # We add a goto instruction
        insert_goto_instruction(blk, blk_successor_serial, nop_previous_instruction=False)
    elif blk.tail.opcode == m_goto:
        # We change goto target directly
        blk.tail.l.make_blkref(blk_successor_serial)
    elif blk.tail.opcode == m_ijmp:
        # We replace ijmp instruction with goto instruction
        insert_goto_instruction(blk, blk_successor_serial, nop_previous_instruction=True)
    elif blk.tail.opcode == m_call:
        #  Before maturity MMAT_CALLS, we can't add a goto after a call instruction
        # if mba.maturity < MMAT_CALLS:
        #     return change_1way_call_block_successor(blk, blk_successor_serial)
        # else:
            insert_goto_instruction(blk, blk_successor_serial, nop_previous_instruction=False)
    else:
        # We add a goto instruction
        insert_goto_instruction(blk, blk_successor_serial, nop_previous_instruction=False)

    # Update block properties
    blk.type = BLT_1WAY
    blk.flags |= MBL_GOTO

    # Bookkeeping
    blk.succset._del(previous_blk_successor_serial)
    blk.succset.push_back(blk_successor_serial)
    blk.mark_lists_dirty()

    previous_blk_successor.predset._del(blk.serial)
    if previous_blk_successor.serial != mba.qty - 1:
        previous_blk_successor.mark_lists_dirty()

    new_blk_successor = blk.mba.get_mblock(blk_successor_serial)
    new_blk_successor.predset.push_back(blk.serial)

    if new_blk_successor.serial != mba.qty - 1:
        new_blk_successor.mark_lists_dirty()

    # mba.mark_chains_dirty()
    try:
        mba.verify(True)
        return True
    except RuntimeError as e:
        print("Error in change_1way_block_successor: {0}".format(e))
        raise e




class blkOPt(hr.optblock_t):

    def func(self, blk):
        if blk.head is None:
            return 0
        print(blk.mba.maturity, hex(blk.head.ea), blk.serial)
        if blk.mba.maturity != hr.MMAT_GLBOPT2:
            return 0
        # import pydevd_pycharm
        # pydevd_pycharm.settrace('localhost', port=31235, stdoutToServer=True, s tderrToServer=True)


        if blk.serial == 8:
            if blk.succset[0] == 5:
                return 0
            print("First only ->>>>>>>>>>>>>>>>>>>>>>")
            blk_8 = None
            blk_1 = None
            for blk_idx in range(blk.mba.qty):
                blk_mtp = blk.mba.get_mblock(blk_idx)
                if blk_mtp.serial == 1:
                    blk_1 = blk_mtp

                if blk_mtp.serial == 8:
                    blk_8 = blk_mtp

            change_1way_block_successor(blk_1, 6)
            change_1way_block_successor(blk_8, 5)
            return 1
        # return 0

        # if blk.serial == 1:
        #     print( "blkOPt 1 ->",blk.succset[0])
        #     if blk.succset[0] ==6:
        #         return 0
        #     change_1way_block_successor(blk,6)
        #     print( "blkOPt  modify 1 ->",blk.succset[0])
        #     return 1
        #
        # if blk.serial == 8:
        #     print( "blkOPt 8 ->",blk.succset[0])
        #     if blk.succset[0] == 10:
        #         return 0
        #     change_1way_block_successor(blk,10)
        #     print( "blkOPt  modify 8 ->",blk.succset[0])
        #     return 1
        #
        # if blk.serial == 9:
        #     print( "blkOPt 9",blk.succset[0])
        #     if blk.succset[0] == 5:
        #         return 0
        #     change_1way_block_successor(blk,5)
        #     print( "blkOPt 9",blk.succset[0])
        #     return 1
        #
        # if blk.serial == 10:
        #     print( "blkOPt 10",blk.succset[0])
        #     if blk.succset[0] == 5:
        #         return 0
        #     change_1way_block_successor(blk,5)
        #     print( "blkOPt 10",blk.succset[0])
        #     return 1
        return 0



if __name__ == '__main__':  # 也可以直接在脚本里执行
    hr.clear_cached_cfuncs()

    try:
        optimizer = blkOPt()
        optimizer.install()
    except Exception as e:
        logging.exception(e)
