/******************************************************************************
 *
 * Copyright(c) 2003 - 2014 Intel Corporation. All rights reserved.
 * Copyright(c) 2013 - 2015 Intel Mobile Communications GmbH
 * Copyright(c) 2016 - 2017 Intel Deutschland GmbH
 *
 * Portions of this file are derived from the ipw3945 project, as well
 * as portions of the ieee80211 subsystem header files.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of version 2 of the GNU General Public License as
 * published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
 * more details.
 *
 * You should have received a copy of the GNU General Public License along with
 * this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110, USA
 *
 * The full GNU General Public License is included in this distribution in the
 * file called LICENSE.
 *
 * Contact Information:
 *  Intel Linux Wireless <linuxwifi@intel.com>
 * Intel Corporation, 5200 N.E. Elam Young Parkway, Hillsboro, OR 97124-6497
 *
 *****************************************************************************/

//
//  IntelWifi_rx.cpp
//  IntelWifi
//
//  Created by Roman Peshkov on 02/01/2018.
//  Copyright © 2018 Roman Peshkov. All rights reserved.
//

#include "IntelWifi.hpp"
#include "iwlwifi/fw/api/tx.h"

#include "iwlwifi/iwl-trans.h"

#define IWL_TX_CRC_SIZE 4
#define IWL_TX_DELIMITER_SIZE 4

/*************** DMA-QUEUE-GENERAL-FUNCTIONS  *****
 * DMA services
 *
 * Theory of operation
 *
 * A Tx or Rx queue resides in host DRAM, and is comprised of a circular buffer
 * of buffer descriptors, each of which points to one or more data buffers for
 * the device to read from or fill.  Driver and device exchange status of each
 * queue via "read" and "write" pointers.  Driver keeps minimum of 2 empty
 * entries in each circular buffer, to protect against confusing empty and full
 * queue states.
 *
 * The device reads or writes the data in the queues via the device's several
 * DMA/FIFO channels.  Each queue is mapped to a single DMA channel.
 *
 * For Tx queue, there are low mark and high mark limits. If, after queuing
 * the packet for Tx, free space become < low mark, Tx queue stopped. When
 * reclaiming packets (on 'tx done IRQ), if free space become > high mark,
 * Tx queue resumed.
 *
 ***************************************************/

int iwl_queue_space(const struct iwl_txq *q)
{
    unsigned int max;
    unsigned int used;
    
    /*
     * To avoid ambiguity between empty and completely full queues, there
     * should always be less than TFD_QUEUE_SIZE_MAX elements in the queue.
     * If q->n_window is smaller than TFD_QUEUE_SIZE_MAX, there is no need
     * to reserve any queue entries for this purpose.
     */
    if (q->n_window < TFD_QUEUE_SIZE_MAX)
        max = q->n_window;
    else
        max = TFD_QUEUE_SIZE_MAX - 1;
    
    /*
     * TFD_QUEUE_SIZE_MAX is a power of 2, so the following is equivalent to
     * modulo by TFD_QUEUE_SIZE_MAX and is well defined.
     */
    used = (q->write_ptr - q->read_ptr) & (TFD_QUEUE_SIZE_MAX - 1);
    
    if (WARN_ON(used > max))
        return 0;
    
    return max - used;
}

/*
 * iwl_queue_init - Initialize queue's high/low-water and read/write indexes
 */
static int iwl_queue_init(struct iwl_txq *q, int slots_num)
{
    q->n_window = slots_num;
    
    /* slots_num must be power-of-two size, otherwise
     * iwl_pcie_get_cmd_index is broken. */
    if (WARN_ON(!is_power_of_2(slots_num)))
        return -EINVAL;
    
    q->low_mark = q->n_window / 4;
    if (q->low_mark < 4)
        q->low_mark = 4;
    
    q->high_mark = q->n_window / 8;
    if (q->high_mark < 2)
        q->high_mark = 2;
    
    q->write_ptr = 0;
    q->read_ptr = 0;
    
    return 0;
}

// line 127
int iwl_pcie_alloc_dma_ptr(struct iwl_trans *trans, struct iwl_dma_ptr **ptr, size_t size)
{
    if (*ptr && (*ptr)->addr) {
        return -EINVAL;
    }
    
    struct iwl_trans_pcie *trans_pcie = IWL_TRANS_GET_PCIE_TRANS(trans);
    *ptr = allocate_dma_buf(size, DMA_BIT_MASK(trans_pcie->addr_size));
    if (!(*ptr)) {
        return -ENOMEM;
    }
    return 0;
}

// line 141
void iwl_pcie_free_dma_ptr(struct iwl_trans *trans, struct iwl_dma_ptr *ptr)
{
    if (unlikely(!ptr->addr))
        return;
    
    free_dma_buf(ptr);
    //memset(ptr, 0, sizeof(*ptr));
}



// line 217
static void iwl_pcie_txq_inval_byte_cnt_tbl(struct iwl_trans *trans, struct iwl_txq *txq)
{
    struct iwl_trans_pcie *trans_pcie =
    IWL_TRANS_GET_PCIE_TRANS(trans);
    struct iwlagn_scd_bc_tbl *scd_bc_tbl = (struct iwlagn_scd_bc_tbl *)trans_pcie->scd_bc_tbls->addr;
    int txq_id = txq->id;
    int read_ptr = txq->read_ptr;
    u8 sta_id = 0;
    __le16 bc_ent;
    struct iwl_tx_cmd *tx_cmd = (struct iwl_tx_cmd *)txq->entries[read_ptr].cmd->payload;
    
    if (read_ptr >= TFD_QUEUE_SIZE_MAX) {
        IWL_WARN(trans, "read_ptr >= TFD_QUEUE_SIZE_MAX");
    }
    
    if (txq_id != trans_pcie->cmd_queue)
        sta_id = tx_cmd->sta_id;
    
    bc_ent = cpu_to_le16(1 | (sta_id << 12));
    
    scd_bc_tbl[txq_id].tfd_offset[read_ptr] = bc_ent;
    
    if (read_ptr < TFD_QUEUE_SIZE_BC_DUP)
        scd_bc_tbl[txq_id].tfd_offset[TFD_QUEUE_SIZE_MAX + read_ptr] = bc_ent;
}


/* line 244
 * iwl_pcie_txq_inc_wr_ptr - Send new write index to hardware
 */
static void iwl_pcie_txq_inc_wr_ptr(struct iwl_trans *trans, struct iwl_txq *txq)
{
    struct iwl_trans_pcie *trans_pcie = IWL_TRANS_GET_PCIE_TRANS(trans);
    u32 reg = 0;
    int txq_id = txq->id;
    
    //lockdep_assert_held(&txq->lock);
    
    /*
     * explicitly wake up the NIC if:
     * 1. shadow registers aren't enabled
     * 2. NIC is woken up for CMD regardless of shadow outside this function
     * 3. there is a chance that the NIC is asleep
     */
    if (!trans->cfg->base_params->shadow_reg_enable
    && txq_id != trans_pcie->cmd_queue
    && test_bit(STATUS_TPOWER_PMI, &trans->status)) {
        /*
         * wake up nic if it's powered down ...
         * uCode will wake up, and interrupt us again, so next
         * time we'll skip this part.
         */
        reg = iwl_read32(trans, CSR_UCODE_DRV_GP1);
        
        if (reg & CSR_UCODE_DRV_GP1_BIT_MAC_SLEEP) {
            IWL_DEBUG_INFO(trans, "Tx queue %d requesting wakeup, GP1 = 0x%x\n", txq_id, reg);
            iwl_set_bit(trans, CSR_GP_CNTRL, CSR_GP_CNTRL_REG_FLAG_MAC_ACCESS_REQ);
            txq->need_update = true;
            return;
        }
    }
    
    /*
     * if not in power-save mode, uCode will never sleep when we're
     * trying to tx (during RFKILL, we're not trying to tx).
     */
    IWL_DEBUG_TX(trans, "Q:%d WR: 0x%x\n", txq_id, txq->write_ptr);
    if (!txq->block)
        iwl_write32(trans, HBUS_TARG_WRPTR, txq->write_ptr | (txq_id << 8));
}

// line 292
void iwl_pcie_txq_check_wrptrs(struct iwl_trans *trans)
{
    struct iwl_trans_pcie *trans_pcie = IWL_TRANS_GET_PCIE_TRANS(trans);
    int i;
    
    for (i = 0; i < trans->cfg->base_params->num_of_queues; i++) {
        struct iwl_txq *txq = trans_pcie->txq[i];
        
        if (!test_bit(i, trans_pcie->queue_used))
            continue;

        //spin_lock_bh(&txq->lock);
        //IOSimpleLockLock(txq->lock);
        if (txq->need_update) {
            iwl_pcie_txq_inc_wr_ptr(trans, txq);
            txq->need_update = false;
        }
        //spin_unlock_bh(&txq->lock);
        //IOSimpleLockUnlock(txq->lock);
    }
}

// line 312
static dma_addr_t iwl_pcie_tfd_tb_get_addr(struct iwl_trans *trans, void *_tfd, u8 idx)
{
    if (trans->cfg->use_tfh) {
        struct iwl_tfh_tfd *tfd = (struct iwl_tfh_tfd *)_tfd;
        struct iwl_tfh_tb *tb = &tfd->tbs[idx];
        
        return (dma_addr_t)(le64_to_cpu(tb->addr));
    } else {
        struct iwl_tfd *tfd = (struct iwl_tfd *)_tfd;
        struct iwl_tfd_tb *tb = &tfd->tbs[idx];
        dma_addr_t addr = get_unaligned_le32(&tb->lo);
        dma_addr_t hi_len;
        
        if (sizeof(dma_addr_t) <= sizeof(u32))
            return addr;
        
        hi_len = le16_to_cpu(tb->hi_n_len) & 0xF;
        
        /*
         * shift by 16 twice to avoid warnings on 32-bit
         * (where this code never runs anyway due to the
         * if statement above)
         */
        return addr | ((hi_len << 16) << 16);
    }
}


// line 341
static void iwl_pcie_tfd_set_tb(struct iwl_trans *trans, void *tfd, u8 idx, dma_addr_t addr, u16 len)
{
    struct iwl_tfd *tfd_fh = (struct iwl_tfd *)tfd;
    struct iwl_tfd_tb *tb = &tfd_fh->tbs[idx];
    
    u16 hi_n_len = len << 4;
    
    put_unaligned_le32((u32)addr, &tb->lo);
    hi_n_len |= iwl_get_dma_hi_addr(addr);
    
    tb->hi_n_len = cpu_to_le16(hi_n_len);
    
    tfd_fh->num_tbs = idx + 1;
}

// line 357
static u8 iwl_pcie_tfd_get_num_tbs(struct iwl_trans *trans, void *_tfd)
{
    if (trans->cfg->use_tfh) {
        struct iwl_tfh_tfd *tfd = (struct iwl_tfh_tfd *)_tfd;
        
        return le16_to_cpu(tfd->num_tbs) & 0x1f;
    } else {
        struct iwl_tfd *tfd = (struct iwl_tfd *)_tfd;
        
        return tfd->num_tbs & 0x1f;
    }
}

// line 370
static void iwl_pcie_tfd_unmap(struct iwl_trans *trans, struct iwl_cmd_meta *meta, struct iwl_txq *txq, int index)
{
    struct iwl_trans_pcie *trans_pcie = IWL_TRANS_GET_PCIE_TRANS(trans);
    int i, num_tbs;
    void *tfd = iwl_pcie_get_tfd(trans_pcie, txq, index);
    
    /* Sanity check on number of chunks */
    num_tbs = iwl_pcie_tfd_get_num_tbs(trans, tfd);
    
    if (num_tbs >= trans_pcie->max_tbs) {
        IWL_ERR(trans, "Too many chunks: %i\n", num_tbs);
        /* @todo issue fatal error, it is quite serious situation */
        return;
    }

    // Since working with DMA is quite different in OSX, unmapping is basically just freeing of buffer descriptors
    // that were previously allocated
    for (i = 0; i < ARRAY_SIZE(meta->dma); ++i) {
        if (meta->dma[i]) {
            free_dma_buf(meta->dma[i]);
        }
        meta->dma[i] = NULL;
    }
    
    /* first TB is never freed - it's the bidirectional DMA data */
//    for (i = 1; i < num_tbs; i++) {
//        if (meta->tbs & BIT(i))
//            dma_unmap_page(trans->dev,
//                           iwl_pcie_tfd_tb_get_addr(trans, tfd, i),
//                           iwl_pcie_tfd_tb_get_len(trans, tfd, i),
//                           DMA_TO_DEVICE);
//        else
//            dma_unmap_single(trans->dev,
//                             iwl_pcie_tfd_tb_get_addr(trans, tfd, i),
//                             iwl_pcie_tfd_tb_get_len(trans, tfd, i),
//                             DMA_TO_DEVICE);
//    }
    
    if (trans->cfg->use_tfh) {
        struct iwl_tfh_tfd *tfd_fh = (struct iwl_tfh_tfd *)tfd;
        
        tfd_fh->num_tbs = 0;
    } else {
        struct iwl_tfd *tfd_fh = (struct iwl_tfd *)tfd;
        
        tfd_fh->num_tbs = 0;
    }
    
}

/* line 416
 * iwl_pcie_txq_free_tfd - Free all chunks referenced by TFD [txq->q.read_ptr]
 * @trans - transport private data
 * @txq - tx queue
 * @dma_dir - the direction of the DMA mapping
 *
 * Does NOT advance any TFD circular buffer read/write indexes
 * Does NOT free the TFD itself (which is within circular buffer)
 */
void iwl_pcie_txq_free_tfd(struct iwl_trans *trans, struct iwl_txq *txq)
{
    /* rd_ptr is bounded by TFD_QUEUE_SIZE_MAX and
     * idx is bounded by n_window
     */
    int rd_ptr = txq->read_ptr;
    int idx = iwl_pcie_get_cmd_index(txq, rd_ptr);
    
    //lockdep_assert_held(&txq->lock);
    
    /* We have only q->n_window txq->entries, but we use
     * TFD_QUEUE_SIZE_MAX tfds
     */
    iwl_pcie_tfd_unmap(trans, &txq->entries[idx].meta, txq, rd_ptr);
    
    /* free SKB */
    if (txq->entries) {
        struct sk_buff *skb;
        
        skb = txq->entries[idx].skb;
        
        /* Can be called from irqs-disabled context
         * If skb is not NULL, it means that the whole queue is being
         * freed and that the queue is not empty - free the skb
         */
        if (skb) {
            // TODO: Implement
            // iwl_op_mode_free_skb(trans->op_mode, skb);
            txq->entries[idx].skb = NULL;
        }
    }
}

// line 457
static int iwl_pcie_txq_build_tfd(struct iwl_trans *trans, struct iwl_txq *txq, dma_addr_t addr, u16 len, bool reset)
{
    struct iwl_trans_pcie *trans_pcie = IWL_TRANS_GET_PCIE_TRANS(trans);
    void *tfd;
    u32 num_tbs;
    
    tfd = (u8*)txq->tfds + trans_pcie->tfd_size * txq->write_ptr;
    
    if (reset)
        memset(tfd, 0, trans_pcie->tfd_size);
    
    num_tbs = iwl_pcie_tfd_get_num_tbs(trans, tfd);
    
    /* Each TFD can point to a maximum max_tbs Tx buffers */
    if (num_tbs >= trans_pcie->max_tbs) {
        IWL_ERR(trans, "Error can not send more than %d chunks\n", trans_pcie->max_tbs);
        return -EINVAL;
    }
    
    if (addr & ~IWL_TX_DMA_MASK)
        return -EINVAL;
    
    iwl_pcie_tfd_set_tb(trans, tfd, num_tbs, addr, len);
    
    return num_tbs;
}


// line 487
int IntelWifi::iwl_pcie_txq_alloc(struct iwl_trans *trans, struct iwl_txq *txq, int slots_num, bool cmd_queue)
{
    struct iwl_trans_pcie *trans_pcie = IWL_TRANS_GET_PCIE_TRANS(trans);
    size_t tfd_sz = trans_pcie->tfd_size * TFD_QUEUE_SIZE_MAX;
    size_t tb0_buf_sz;
    int i;
    int ret;
    struct iwl_dma_ptr *tfds_dma = NULL;
    struct iwl_dma_ptr *first_tb_bufs_dma = NULL;

    if (WARN_ON(txq->entries || txq->tfds))
        return -EINVAL;

    // TODO: Implement
//    setup_timer(&txq->stuck_timer, iwl_pcie_txq_stuck_timer, (unsigned long)txq);
    txq->trans_pcie = trans_pcie;
    
    txq->n_window = slots_num;
    
    txq->entries = (struct iwl_pcie_txq_entry *) IOMalloc(sizeof(struct iwl_pcie_txq_entry) * slots_num);
    
    if (!txq->entries)
        goto error;

    bzero(txq->entries, sizeof(struct iwl_pcie_txq_entry) * slots_num);
    if (cmd_queue)
        for (i = 0; i < slots_num; i++) {
            txq->entries[i].cmd = (struct iwl_device_cmd *)IOMalloc(sizeof(struct iwl_device_cmd));
            if (!txq->entries[i].cmd)
                goto error;
        }

    /* Circular buffer of transmit frame descriptors (TFDs),
     * shared with device */
    ret = iwl_pcie_alloc_dma_ptr(trans, &tfds_dma, tfd_sz);
    if (ret) {
        goto error;
    }

    txq->tfds_dma_ptr = tfds_dma;
    txq->tfds = tfds_dma->addr;
    txq->dma_addr = tfds_dma->dma;
   
    tb0_buf_sz = sizeof(*txq->first_tb_bufs) * slots_num;
    
    ret = iwl_pcie_alloc_dma_ptr(trans, &first_tb_bufs_dma, tb0_buf_sz);
    if (ret) {
        goto err_free_tfds;
    }

    txq->first_tb_dma_ptr = first_tb_bufs_dma;
    txq->first_tb_bufs = (struct iwl_pcie_first_tb_buf *)first_tb_bufs_dma->addr;
    txq->first_tb_dma = first_tb_bufs_dma->dma;
    
    return 0;
err_free_tfds:
    free_dma_buf(txq->tfds_dma_ptr);
error:
    if (txq->entries && cmd_queue)
        for (i = 0; i < slots_num; i++)
            IOFree(txq->entries[i].cmd, sizeof(struct iwl_device_cmd));

    IOFree(txq->entries, sizeof(struct iwl_pcie_txq_entry) * slots_num);
    txq->entries = NULL;
    return -ENOMEM;
    
}

// line 551
int IntelWifi::iwl_pcie_txq_init(struct iwl_trans *trans, struct iwl_txq *txq, int slots_num, bool cmd_queue)
{
    int ret;
    
    txq->need_update = false;
    
    /* TFD_QUEUE_SIZE_MAX must be power-of-two size, otherwise
     * iwl_queue_inc_wrap and iwl_queue_dec_wrap are broken. */
    BUILD_BUG_ON(TFD_QUEUE_SIZE_MAX & (TFD_QUEUE_SIZE_MAX - 1));
    
    /* Initialize queue's high/low-water marks, and head/tail indexes */
    ret = iwl_queue_init(txq, slots_num);
    if (ret)
        return ret;
    
    txq->lock = IOSimpleLockAlloc();
    
    if (cmd_queue) {
        // TODO: Implement
//        static struct lock_class_key iwl_pcie_cmd_queue_lock_class;
//
//        lockdep_set_class(&txq->lock, &iwl_pcie_cmd_queue_lock_class);
    }
    
    // TODO: Implement
    //__skb_queue_head_init(&txq->overflow_q);
    
    return 0;
}

// line 593
static void iwl_pcie_clear_cmd_in_flight(struct iwl_trans *trans)
{
    struct iwl_trans_pcie *trans_pcie = IWL_TRANS_GET_PCIE_TRANS(trans);
    
    //lockdep_assert_held(&trans_pcie->reg_lock);
    
    if (trans_pcie->ref_cmd_in_flight) {
        trans_pcie->ref_cmd_in_flight = false;
        IWL_DEBUG_RPM(trans, "clear ref_cmd_in_flight - unref\n");
        iwl_trans_unref(trans);
    }
    
    if (!trans->cfg->base_params->apmg_wake_up_wa)
        return;
    
    if (WARN_ON(!trans_pcie->cmd_hold_nic_awake))
        return;
    
    trans_pcie->cmd_hold_nic_awake = false;
    __iwl_trans_pcie_clear_bit(trans, CSR_GP_CNTRL, CSR_GP_CNTRL_REG_FLAG_MAC_ACCESS_REQ);
}

/* line 615
 * iwl_pcie_txq_unmap -  Unmap any remaining DMA mappings and free skb's
 */
static void iwl_pcie_txq_unmap(struct iwl_trans *trans, int txq_id)
{
    struct iwl_trans_pcie *trans_pcie = IWL_TRANS_GET_PCIE_TRANS(trans);
    struct iwl_txq *txq = trans_pcie->txq[txq_id];
    
    //spin_lock_bh(&txq->lock);
    while (txq->write_ptr != txq->read_ptr) {
        IWL_DEBUG_TX_REPLY(trans, "Q %d Free %d\n", txq_id, txq->read_ptr);
        
        if (txq_id != trans_pcie->cmd_queue) {
            struct sk_buff *skb = txq->entries[txq->read_ptr].skb;
            
            if (WARN_ON_ONCE(!skb))
                continue;
            
            // TODO: Implement
            // iwl_pcie_free_tso_page(trans_pcie, skb);
        }
        iwl_pcie_txq_free_tfd(trans, txq);
        txq->read_ptr = iwl_queue_inc_wrap(txq->read_ptr);
        
        if (txq->read_ptr == txq->write_ptr) {
            // unsigned long flags;
            
            //spin_lock_irqsave(&trans_pcie->reg_lock, flags);
            if (txq_id != trans_pcie->cmd_queue) {
                IWL_DEBUG_RPM(trans, "Q %d - last tx freed\n", txq->id);
                iwl_trans_unref(trans);
            } else {
                iwl_pcie_clear_cmd_in_flight(trans);
            }
            //spin_unlock_irqrestore(&trans_pcie->reg_lock, flags);
        }
    }

    // TODO: Implement
//    while (!skb_queue_empty(&txq->overflow_q)) {
//        struct sk_buff *skb = __skb_dequeue(&txq->overflow_q);
//
//        iwl_op_mode_free_skb(trans->op_mode, skb);
//    }
    
    //spin_unlock_bh(&txq->lock);
    
    /* just in case - this queue may have been stopped */
    // TODO: Implement
    // iwl_wake_queue(trans, txq);
}



/* line 666
 * iwl_pcie_txq_free - Deallocate DMA queue.
 * @txq: Transmit queue to deallocate.
 *
 * Empty queue by removing and destroying all BD's.
 * Free all buffers.
 * 0-fill, but do not free "txq" descriptor structure.
 */
static void iwl_pcie_txq_free(struct iwl_trans *trans, int txq_id)
{
    struct iwl_trans_pcie *trans_pcie = IWL_TRANS_GET_PCIE_TRANS(trans);
    struct iwl_txq *txq = trans_pcie->txq[txq_id];
    //struct device *dev = trans->dev;
    int i;
    
    if (WARN_ON(!txq))
        return;
    
    iwl_pcie_txq_unmap(trans, txq_id);
    
    /* De-alloc array of command/tx buffers */
    if (txq_id == trans_pcie->cmd_queue)
        for (i = 0; i < txq->n_window; i++) {
            IOFree(txq->entries[i].cmd, sizeof(struct iwl_device_cmd));
            // TODO: Implement
            //kzfree(txq->entries[i].free_buf);
        }
    
    /* De-alloc circular buffer of TFDs */
    if (txq->tfds) {
        free_dma_buf(txq->tfds_dma_ptr);
        txq->dma_addr = 0;
        txq->tfds = NULL;
        
        free_dma_buf(txq->first_tb_dma_ptr);
    }
    
    IOFree(txq->entries, sizeof(struct iwl_pcie_txq_entry) * txq->n_window);
    txq->entries = NULL;
    
    //del_timer_sync(&txq->stuck_timer);
    
    /* 0-fill queue descriptor structure */
    bzero(txq, sizeof(*txq));
}



// line 715
void iwl_pcie_tx_start(struct iwl_trans *trans, u32 scd_base_addr)
{
    struct iwl_trans_pcie *trans_pcie = IWL_TRANS_GET_PCIE_TRANS(trans);
    int nq = trans->cfg->base_params->num_of_queues;
    int chan;
    u32 reg_val;
    int clear_dwords = (SCD_TRANS_TBL_OFFSET_QUEUE(nq) - SCD_CONTEXT_MEM_LOWER_BOUND) / sizeof(u32);
    
    /* make sure all queue are not stopped/used */
    memset(trans_pcie->queue_stopped, 0, sizeof(trans_pcie->queue_stopped));
    memset(trans_pcie->queue_used, 0, sizeof(trans_pcie->queue_used));
    
    trans_pcie->scd_base_addr =
    iwl_read_prph(trans, SCD_SRAM_BASE_ADDR);
    
    if (scd_base_addr != 0 && scd_base_addr != trans_pcie->scd_base_addr) {
        IWL_WARN(trans, "scd_base_addr != 0 && scd_base_addr != trans_pcie->scd_base_addr");
    }
    
    /* reset context data, TX status and translation data */
    iwl_trans_write_mem(trans, trans_pcie->scd_base_addr + SCD_CONTEXT_MEM_LOWER_BOUND, NULL, clear_dwords);
    
    iwl_write_prph(trans, SCD_DRAM_BASE_ADDR, (u32)trans_pcie->scd_bc_tbls->dma >> 10);
    
    /* The chain extension of the SCD doesn't work well. This feature is
     * enabled by default by the HW, so we need to disable it manually.
     */
    if (trans->cfg->base_params->scd_chain_ext_wa)
        iwl_write_prph(trans, SCD_CHAINEXT_EN, 0);
    
    iwl_trans_ac_txq_enable(trans, trans_pcie->cmd_queue, trans_pcie->cmd_fifo, trans_pcie->cmd_q_wdg_timeout);
    
    /* Activate all Tx DMA/FIFO channels */
    iwl_scd_activate_fifos(trans);
    
    /* Enable DMA channel */
    for (chan = 0; chan < FH_TCSR_CHNL_NUM; chan++)
        iwl_write_direct32(trans, FH_TCSR_CHNL_TX_CONFIG_REG(chan),
                           FH_TCSR_TX_CONFIG_REG_VAL_DMA_CHNL_ENABLE |
                           FH_TCSR_TX_CONFIG_REG_VAL_DMA_CREDIT_ENABLE);
    
    /* Update FH chicken bits */
    reg_val = iwl_read_direct32(trans, FH_TX_CHICKEN_BITS_REG);
    iwl_write_direct32(trans, FH_TX_CHICKEN_BITS_REG, reg_val | FH_TX_CHICKEN_BITS_SCD_AUTO_RETRY_EN);
    
    /* Enable L1-Active */
    if (trans->cfg->device_family < IWL_DEVICE_FAMILY_8000)
        iwl_clear_bits_prph(trans, APMG_PCIDEV_STT_REG, APMG_PCIDEV_STT_VAL_L1_ACT_DIS);
}

// line 812
static void iwl_pcie_tx_stop_fh(struct iwl_trans *trans)
{
    struct iwl_trans_pcie *trans_pcie = IWL_TRANS_GET_PCIE_TRANS(trans);
    IOInterruptState state;
    int ch, ret;
    u32 mask = 0;

    //IOSimpleLockLock(trans_pcie->irq_lock);
    
    if (!iwl_trans_grab_nic_access(trans, &state))
        goto out;
    
    /* Stop each Tx DMA channel */
    for (ch = 0; ch < FH_TCSR_CHNL_NUM; ch++) {
        iwl_write32(trans, FH_TCSR_CHNL_TX_CONFIG_REG(ch), 0x0);
        mask |= FH_TSSR_TX_STATUS_REG_MSK_CHNL_IDLE(ch);
    }
    
    /* Wait for DMA channels to be idle */
    ret = iwl_poll_bit(trans, FH_TSSR_TX_STATUS_REG, mask, mask, 5000);
    if (ret < 0)
        IWL_ERR(trans, "Failing on timeout while stopping DMA channel %d [0x%08x]\n",
                ch, iwl_read32(trans, FH_TSSR_TX_STATUS_REG));
    
    iwl_trans_release_nic_access(trans, &state);
    
out:
    //IOSimpleLockUnlock(trans_pcie->irq_lock);
    return;
}

/* line 843
 * iwl_pcie_tx_stop - Stop all Tx DMA channels
 */
int iwl_pcie_tx_stop(struct iwl_trans *trans)
{
    struct iwl_trans_pcie *trans_pcie = IWL_TRANS_GET_PCIE_TRANS(trans);
    int txq_id;
    
    /* Turn off all Tx DMA fifos */
    iwl_scd_deactivate_fifos(trans);
    
    /* Turn off all Tx DMA channels */
    iwl_pcie_tx_stop_fh(trans);
    
    /*
     * This function can be called before the op_mode disabled the
     * queues. This happens when we have an rfkill interrupt.
     * Since we stop Tx altogether - mark the queues as stopped.
     */
    memset(trans_pcie->queue_stopped, 0, sizeof(trans_pcie->queue_stopped));
    memset(trans_pcie->queue_used, 0, sizeof(trans_pcie->queue_used));
    
    /* This can happen: start_hw, stop_device */
    if (!trans_pcie->txq_memory)
        return 0;
    
    /* Unmap DMA from host system and free skb's */
    for (txq_id = 0; txq_id < trans->cfg->base_params->num_of_queues; txq_id++)
        iwl_pcie_txq_unmap(trans, txq_id);
    
    return 0;
}


/* line 877
 * iwl_trans_tx_free - Free TXQ Context
 *
 * Destroy all TX DMA queues and structures
 */
void iwl_pcie_tx_free(struct iwl_trans *trans)
{
    int txq_id;
    struct iwl_trans_pcie *trans_pcie = IWL_TRANS_GET_PCIE_TRANS(trans);
    
    memset(trans_pcie->queue_used, 0, sizeof(trans_pcie->queue_used));
    
    /* Tx queues */
    if (trans_pcie->txq_memory) {
        for (txq_id = 0; txq_id < trans->cfg->base_params->num_of_queues; txq_id++) {
            iwl_pcie_txq_free(trans, txq_id);
            trans_pcie->txq[txq_id] = NULL;
        }
    }
    
    IOFree(trans_pcie->txq_memory, sizeof(struct iwl_txq) * trans->cfg->base_params->num_of_queues);
    trans_pcie->txq_memory = NULL;
    
    iwl_pcie_free_dma_ptr(trans, trans_pcie->kw);
    iwl_pcie_free_dma_ptr(trans, trans_pcie->scd_bc_tbls);
}


/* line 907
 * iwl_pcie_tx_alloc - allocate TX context
 * Allocate all Tx DMA structures and initialize them
 */
int IntelWifi::iwl_pcie_tx_alloc(struct iwl_trans *trans)
{
    int ret;
    int txq_id, slots_num;
    struct iwl_trans_pcie *trans_pcie = IWL_TRANS_GET_PCIE_TRANS(trans);
    
    u16 scd_bc_tbls_size = trans->cfg->base_params->num_of_queues * sizeof(struct iwlagn_scd_bc_tbl);
    
    /*It is not allowed to alloc twice, so warn when this happens.
     * We cannot rely on the previous allocation, so free and fail */
    if (WARN_ON(trans_pcie->txq_memory)) {
        ret = -EINVAL;
        goto error;
    }
    trans_pcie->scd_bc_tbls = 0;
    ret = iwl_pcie_alloc_dma_ptr(trans, &trans_pcie->scd_bc_tbls, scd_bc_tbls_size);
    if (ret) {
        IWL_ERR(trans, "Scheduler BC Table allocation failed\n");
        goto error;
    }
    
    trans_pcie->kw = 0;
    /* Alloc keep-warm buffer */
    ret = iwl_pcie_alloc_dma_ptr(trans, &trans_pcie->kw, IWL_KW_SIZE);
    if (ret) {
        IWL_ERR(trans, "Keep Warm allocation failed\n");
        goto error;
    }

    trans_pcie->txq_memory = (struct iwl_txq *)IOMalloc(sizeof(struct iwl_txq) * trans->cfg->base_params->num_of_queues);
    if (!trans_pcie->txq_memory) {
        IWL_ERR(trans, "Not enough memory for txq\n");
        ret = -ENOMEM;
        goto error;
    }
    bzero(trans_pcie->txq_memory, sizeof(struct iwl_txq) * trans->cfg->base_params->num_of_queues);
    
    /* Alloc and init all Tx queues, including the command queue (#4/#9) */
    for (txq_id = 0; txq_id < trans->cfg->base_params->num_of_queues; txq_id++) {
        bool cmd_queue = (txq_id == trans_pcie->cmd_queue);
        
        slots_num = cmd_queue ? TFD_CMD_SLOTS : TFD_TX_CMD_SLOTS;
        trans_pcie->txq[txq_id] = &trans_pcie->txq_memory[txq_id];
        ret = iwl_pcie_txq_alloc(trans, trans_pcie->txq[txq_id], slots_num, cmd_queue);
        if (ret) {
            IWL_ERR(trans, "Tx %d queue alloc failed\n", txq_id);
            goto error;
        }
        trans_pcie->txq[txq_id]->id = txq_id;
    }
    
    return 0;
    
error:
    iwl_pcie_tx_free(trans);
    
    return ret;
}


// line 973
int IntelWifi::iwl_pcie_tx_init(struct iwl_trans *trans)
{
    struct iwl_trans_pcie *trans_pcie = IWL_TRANS_GET_PCIE_TRANS(trans);
    int ret;
    int txq_id, slots_num;
    bool alloc = false;
    
    if (!trans_pcie->txq_memory) {
        ret = iwl_pcie_tx_alloc(trans);
        if (ret)
            goto error;
        alloc = true;
    }
    
    //IOSimpleLockLock(trans_pcie->irq_lock);
    
    /* Turn off all Tx DMA fifos */
    iwl_scd_deactivate_fifos(trans);
    
    /* Tell NIC where to find the "keep warm" buffer */
    iwl_write_direct32(trans, FH_KW_MEM_ADDR_REG, (u32)trans_pcie->kw->dma >> 4);
    
    // spin_unlock(&trans_pcie->irq_lock);
    //IOSimpleLockUnlock(trans_pcie->irq_lock);
    
    /* Alloc and init all Tx queues, including the command queue (#4/#9) */
    for (txq_id = 0; txq_id < trans->cfg->base_params->num_of_queues; txq_id++) {
        bool cmd_queue = (txq_id == trans_pcie->cmd_queue);
        
        slots_num = cmd_queue ? TFD_CMD_SLOTS : TFD_TX_CMD_SLOTS;
        ret = iwl_pcie_txq_init(trans, trans_pcie->txq[txq_id], slots_num, cmd_queue);
        if (ret) {
            IWL_ERR(trans, "Tx %d queue init failed\n", txq_id);
            goto error;
        }
        
        /*
         * Tell nic where to find circular buffer of TFDs for a
         * given Tx queue, and enable the DMA channel used for that
         * queue.
         * Circular buffer (TFD queue in DRAM) physical base address
         */
        iwl_write_direct32(trans, FH_MEM_CBBC_QUEUE(trans, txq_id),
                           (u32)trans_pcie->txq[txq_id]->dma_addr >> 8);
    }
    
    iwl_set_bits_prph(trans, SCD_GP_CTRL, SCD_GP_CTRL_AUTO_ACTIVE_MODE);
    if (trans->cfg->base_params->num_of_queues > 20)
        iwl_set_bits_prph(trans, SCD_GP_CTRL, SCD_GP_CTRL_ENABLE_31_QUEUES);
    
    return 0;
error:
    /*Upon error, free only if we allocated something */
    if (alloc)
        iwl_pcie_tx_free(trans);
    return ret;
}

// line 1034
void IntelWifi::iwl_pcie_txq_progress(struct iwl_txq *txq)
{
    //lockdep_assert_held(&txq->lock);
    
    if (!txq->wd_timeout)
        return;
    
    /*
     * station is asleep and we send data - that must
     * be uAPSD or PS-Poll. Don't rearm the timer.
     */
    if (txq->frozen)
        return;
    
    /*
     * if empty delete timer, otherwise move timer forward
     * since we're making progress on this queue
     */
    // TODO: Implement
//    if (txq->read_ptr == txq->write_ptr)
//        del_timer(&txq->stuck_timer);
//    else
//        mod_timer(&txq->stuck_timer, jiffies + txq->wd_timeout);
}



// line 1168
static int iwl_pcie_set_cmd_in_flight(struct iwl_trans *trans, const struct iwl_host_cmd *cmd)
{
    struct iwl_trans_pcie *trans_pcie = IWL_TRANS_GET_PCIE_TRANS(trans);
    int ret;
    
    //lockdep_assert_held(&trans_pcie->reg_lock);
    
    if (!(cmd->flags & CMD_SEND_IN_IDLE) && !trans_pcie->ref_cmd_in_flight) {
        trans_pcie->ref_cmd_in_flight = true;
        IWL_DEBUG_RPM(trans, "set ref_cmd_in_flight - ref\n");
        iwl_trans_ref(trans);
    }
    
    /*
     * wake up the NIC to make sure that the firmware will see the host
     * command - we will let the NIC sleep once all the host commands
     * returned. This needs to be done only on NICs that have
     * apmg_wake_up_wa set.
     */
    if (trans->cfg->base_params->apmg_wake_up_wa && !trans_pcie->cmd_hold_nic_awake) {
        __iwl_trans_pcie_set_bit(trans, CSR_GP_CNTRL,
                                 CSR_GP_CNTRL_REG_FLAG_MAC_ACCESS_REQ);
        
        ret = iwl_poll_bit(trans, CSR_GP_CNTRL,
                           CSR_GP_CNTRL_REG_VAL_MAC_ACCESS_EN,
                           (CSR_GP_CNTRL_REG_FLAG_MAC_CLOCK_READY |
                            CSR_GP_CNTRL_REG_FLAG_GOING_TO_SLEEP),
                           15000);
        if (ret < 0) {
            __iwl_trans_pcie_clear_bit(trans, CSR_GP_CNTRL, CSR_GP_CNTRL_REG_FLAG_MAC_ACCESS_REQ);
            IWL_ERR(trans, "Failed to wake NIC for hcmd\n");
            return -EIO;
        }
        trans_pcie->cmd_hold_nic_awake = true;
    }
    
    return 0;
}


/* line 1211
 * iwl_pcie_cmdq_reclaim - Reclaim TX command queue entries already Tx'd
 *
 * When FW advances 'R' index, all entries between old and new 'R' index
 * need to be reclaimed. As result, some free space forms.  If there is
 * enough free space (> low mark), wake the stack that feeds us.
 */
void IntelWifi::iwl_pcie_cmdq_reclaim(struct iwl_trans *trans, int txq_id, int idx)
{
    struct iwl_trans_pcie *trans_pcie = IWL_TRANS_GET_PCIE_TRANS(trans);
    struct iwl_txq *txq = trans_pcie->txq[txq_id];
    IOInterruptState state;
    int nfreed = 0;
    
    //lockdep_assert_held(&txq->lock);
    
    if ((idx >= TFD_QUEUE_SIZE_MAX) || (!iwl_queue_used(txq, idx))) {
        IWL_ERR(trans,
                "%s: Read index for DMA queue txq id (%d), index %d is out of range [0-%d] %d %d.\n",
                __func__, txq_id, idx, TFD_QUEUE_SIZE_MAX,
                txq->write_ptr, txq->read_ptr);
        return;
    }
    
    for (idx = iwl_queue_inc_wrap(idx); txq->read_ptr != idx;
         txq->read_ptr = iwl_queue_inc_wrap(txq->read_ptr)) {
        
        if (nfreed++ > 0) {
            IWL_ERR(trans, "HCMD skipped: index (%d) %d %d\n", idx, txq->write_ptr, txq->read_ptr);
            iwl_force_nmi(trans);
        }
    }
    
    if (txq->read_ptr == txq->write_ptr) {
        state = IOSimpleLockLockDisableInterrupt(trans_pcie->reg_lock);
        iwl_pcie_clear_cmd_in_flight(trans);
        IOSimpleLockUnlockEnableInterrupt(trans_pcie->reg_lock, state);
    }
    
    iwl_pcie_txq_progress(txq);
}

// line 1254
static int iwl_pcie_txq_set_ratid_map(struct iwl_trans *trans, u16 ra_tid, u16 txq_id)
{
    struct iwl_trans_pcie *trans_pcie = IWL_TRANS_GET_PCIE_TRANS(trans);
    u32 tbl_dw_addr;
    u32 tbl_dw;
    u16 scd_q2ratid;
    
    scd_q2ratid = ra_tid & SCD_QUEUE_RA_TID_MAP_RATID_MSK;
    
    tbl_dw_addr = trans_pcie->scd_base_addr + SCD_TRANS_TBL_OFFSET_QUEUE(txq_id);
    
    tbl_dw = iwl_trans_read_mem32(trans, tbl_dw_addr);
    
    if (txq_id & 0x1)
        tbl_dw = (scd_q2ratid << 16) | (tbl_dw & 0x0000FFFF);
    else
        tbl_dw = scd_q2ratid | (tbl_dw & 0xFFFF0000);
    
    iwl_trans_write_mem32(trans, tbl_dw_addr, tbl_dw);
    
    return 0;
}


/* Receiver address (actually, Rx station's index into station table),
 * combined with Traffic ID (QOS priority), in format used by Tx Scheduler */
#define BUILD_RAxTID(sta_id, tid)    (((sta_id) << 4) + (tid))

// line 1283
bool iwl_trans_pcie_txq_enable(struct iwl_trans *trans, int txq_id, u16 ssn,
                               const struct iwl_trans_txq_scd_cfg *cfg,
                               unsigned int wdg_timeout)
{
    struct iwl_trans_pcie *trans_pcie = IWL_TRANS_GET_PCIE_TRANS(trans);
    struct iwl_txq *txq = trans_pcie->txq[txq_id];
    int fifo = -1;
    bool scd_bug = false;
    
    if (test_and_set_bit(txq_id, trans_pcie->queue_used)) {
        IWL_DEBUG_TX_QUEUES(trans, "queue %d already used - expect issues", txq_id);
    }
    
    txq->wd_timeout = msecs_to_jiffies(wdg_timeout);
    
    if (cfg) {
        fifo = cfg->fifo;
        
        /* Disable the scheduler prior configuring the cmd queue */
        if (txq_id == trans_pcie->cmd_queue &&
            trans_pcie->scd_set_active)
            iwl_scd_enable_set_active(trans, 0);
        
        /* Stop this Tx queue before configuring it */
        iwl_scd_txq_set_inactive(trans, txq_id);
        
        /* Set this queue as a chain-building queue unless it is CMD */
        if (txq_id != trans_pcie->cmd_queue)
            iwl_scd_txq_set_chain(trans, txq_id);
        
        if (cfg->aggregate) {
            u16 ra_tid = BUILD_RAxTID(cfg->sta_id, cfg->tid);
            
            /* Map receiver-address / traffic-ID to this queue */
            iwl_pcie_txq_set_ratid_map(trans, ra_tid, txq_id);
            
            /* enable aggregations for the queue */
            iwl_scd_txq_enable_agg(trans, txq_id);
            txq->ampdu = true;
        } else {
            /*
             * disable aggregations for the queue, this will also
             * make the ra_tid mapping configuration irrelevant
             * since it is now a non-AGG queue.
             */
            iwl_scd_txq_disable_agg(trans, txq_id);
            
            ssn = txq->read_ptr;
        }
    } else {
        /*
         * If we need to move the SCD write pointer by steps of
         * 0x40, 0x80 or 0xc0, it gets stuck. Avoids this and let
         * the op_mode know by returning true later.
         * Do this only in case cfg is NULL since this trick can
         * be done only if we have DQA enabled which is true for mvm
         * only. And mvm never sets a cfg pointer.
         * This is really ugly, but this is the easiest way out for
         * this sad hardware issue.
         * This bug has been fixed on devices 9000 and up.
         */
        scd_bug = !trans->cfg->mq_rx_supported &&
        !((ssn - txq->write_ptr) & 0x3f) &&
        (ssn != txq->write_ptr);
        if (scd_bug)
            ssn++;
    }
    
    /* Place first TFD at index corresponding to start sequence number.
     * Assumes that ssn_idx is valid (!= 0xFFF) */
    txq->read_ptr = (ssn & 0xff);
    txq->write_ptr = (ssn & 0xff);
    iwl_write_direct32(trans, HBUS_TARG_WRPTR, (ssn & 0xff) | (txq_id << 8));
    
    if (cfg) {
        u8 frame_limit = cfg->frame_limit;
        
        iwl_write_prph(trans, SCD_QUEUE_RDPTR(txq_id), ssn);
        
        /* Set up Tx window size and frame limit for this queue */
        iwl_trans_write_mem32(trans, trans_pcie->scd_base_addr +
                              SCD_CONTEXT_QUEUE_OFFSET(txq_id), 0);
        iwl_trans_write_mem32(trans,
                              trans_pcie->scd_base_addr +
                              SCD_CONTEXT_QUEUE_OFFSET(txq_id) + sizeof(u32),
                              SCD_QUEUE_CTX_REG2_VAL(WIN_SIZE, frame_limit) |
                              SCD_QUEUE_CTX_REG2_VAL(FRAME_LIMIT, frame_limit));
        
        /* Set up status area in SRAM, map to Tx DMA/FIFO, activate */
        iwl_write_prph(trans, SCD_QUEUE_STATUS_BITS(txq_id),
                       (1 << SCD_QUEUE_STTS_REG_POS_ACTIVE) |
                       (cfg->fifo << SCD_QUEUE_STTS_REG_POS_TXF) |
                       (1 << SCD_QUEUE_STTS_REG_POS_WSL) |
                       SCD_QUEUE_STTS_REG_MSK);
        
        /* enable the scheduler for this queue (only) */
        if (txq_id == trans_pcie->cmd_queue && trans_pcie->scd_set_active)
            iwl_scd_enable_set_active(trans, (u32)BIT(txq_id));
        
        IWL_DEBUG_TX_QUEUES(trans,
                            "Activate queue %d on FIFO %d WrPtr: %d\n",
                            txq_id, fifo, ssn & 0xff);
    } else {
        IWL_DEBUG_TX_QUEUES(trans,
                            "Activate queue %d WrPtr: %d\n",
                            txq_id, ssn & 0xff);
    }
    
    return scd_bug;
}

// line 1395
void iwl_trans_pcie_txq_set_shared_mode(struct iwl_trans *trans, u32 txq_id,
                                        bool shared_mode)
{
    struct iwl_trans_pcie *trans_pcie = IWL_TRANS_GET_PCIE_TRANS(trans);
    struct iwl_txq *txq = trans_pcie->txq[txq_id];
    
    txq->ampdu = !shared_mode;
}



// line 1404
void iwl_trans_pcie_txq_disable(struct iwl_trans *trans, int txq_id, bool configure_scd)
{
    struct iwl_trans_pcie *trans_pcie = IWL_TRANS_GET_PCIE_TRANS(trans);
    u32 stts_addr = trans_pcie->scd_base_addr + SCD_TX_STTS_QUEUE_OFFSET(txq_id);
    static const u32 zero_val[4] = {};
    
    trans_pcie->txq[txq_id]->frozen_expiry_remainder = 0;
    trans_pcie->txq[txq_id]->frozen = false;
    
    /*
     * Upon HW Rfkill - we stop the device, and then stop the queues
     * in the op_mode. Just for the sake of the simplicity of the op_mode,
     * allow the op_mode to call txq_disable after it already called
     * stop_device.
     */
    if (!test_and_clear_bit(txq_id, trans_pcie->queue_used)) {
        if (test_bit(STATUS_DEVICE_ENABLED, &trans->status))
            IWL_DEBUG_TX_QUEUES(trans, "queue %d not used", txq_id);
        return;
    }
    
    if (configure_scd) {
        iwl_scd_txq_set_inactive(trans, txq_id);
        
        iwl_trans_write_mem(trans, stts_addr, (void *)zero_val, ARRAY_SIZE(zero_val));
    }
    
    iwl_pcie_txq_unmap(trans, txq_id);
    trans_pcie->txq[txq_id]->ampdu = false;
    
    IWL_DEBUG_TX_QUEUES(trans, "Deactivate queue %d\n", txq_id);
}

/*************** HOST COMMAND QUEUE FUNCTIONS   *****/

/* line 1440
 * iwl_pcie_enqueue_hcmd - enqueue a uCode command
 * @priv: device private data point
 * @cmd: a pointer to the ucode command structure
 *
 * The function returns < 0 values to indicate the operation
 * failed. On success, it returns the index (>= 0) of command in the
 * command queue.
 */
static int iwl_pcie_enqueue_hcmd(struct iwl_trans *trans, struct iwl_host_cmd *cmd)
{
    struct iwl_trans_pcie *trans_pcie = IWL_TRANS_GET_PCIE_TRANS(trans);
    struct iwl_txq *txq = trans_pcie->txq[trans_pcie->cmd_queue];
    struct iwl_device_cmd *out_cmd;
    struct iwl_cmd_meta *out_meta;
    IOInterruptState flags;
    void *dup_buf = NULL;
    vm_size_t dup_buf_size = 0;
    int idx;
    u16 copy_size, cmd_size, tb0_size;
    bool had_nocopy = false;
    u8 group_id = iwl_cmd_groupid(cmd->id);
    int i, ret;
    u32 cmd_pos;
    const u8 *cmddata[IWL_MAX_CMD_TBS_PER_TFD];
    u16 cmdlen[IWL_MAX_CMD_TBS_PER_TFD];
    
    if (!trans->wide_cmd_header && group_id > IWL_ALWAYS_LONG_GROUP)
        return -EINVAL;
    
    if (group_id != 0) {
        copy_size = sizeof(struct iwl_cmd_header_wide);
        cmd_size = sizeof(struct iwl_cmd_header_wide);
    } else {
        copy_size = sizeof(struct iwl_cmd_header);
        cmd_size = sizeof(struct iwl_cmd_header);
    }
    
    /* need one for the header if the first is NOCOPY */
    BUILD_BUG_ON(IWL_MAX_CMD_TBS_PER_TFD > IWL_NUM_OF_TBS - 1);
    
    for (i = 0; i < IWL_MAX_CMD_TBS_PER_TFD; i++) {
        cmddata[i] = (u8*)cmd->data[i];
        cmdlen[i] = cmd->len[i];
        
        if (!cmd->len[i])
            continue;
        
        /* need at least IWL_FIRST_TB_SIZE copied */
        if (copy_size < IWL_FIRST_TB_SIZE) {
            int copy = IWL_FIRST_TB_SIZE - copy_size;
            
            if (copy > cmdlen[i])
                copy = cmdlen[i];
            cmdlen[i] -= copy;
            cmddata[i] += copy;
            copy_size += copy;
        }
        
        if (cmd->dataflags[i] & IWL_HCMD_DFL_NOCOPY) {
            had_nocopy = true;
            if (WARN_ON(cmd->dataflags[i] & IWL_HCMD_DFL_DUP)) {
                idx = -EINVAL;
                goto free_dup_buf;
            }
        } else if (cmd->dataflags[i] & IWL_HCMD_DFL_DUP) {
            /*
             * This is also a chunk that isn't copied
             * to the static buffer so set had_nocopy.
             */
            had_nocopy = true;
            
            /* only allowed once */
            if (WARN_ON(dup_buf)) {
                idx = -EINVAL;
                goto free_dup_buf;
            }
            
            dup_buf = IOMalloc(cmdlen[i]);
            if (!dup_buf)
                return -ENOMEM;
            dup_buf_size = cmdlen[i];
            memcpy(dup_buf, cmddata[i], cmdlen[i]);
           
        } else {
            /* NOCOPY must not be followed by normal! */
            if (WARN_ON(had_nocopy)) {
                idx = -EINVAL;
                goto free_dup_buf;
            }
            copy_size += cmdlen[i];
        }
        cmd_size += cmd->len[i];
    }
    
    /*
     * If any of the command structures end up being larger than
     * the TFD_MAX_PAYLOAD_SIZE and they aren't dynamically
     * allocated into separate TFDs, then we will need to
     * increase the size of the buffers.
     */
    if (copy_size > TFD_MAX_PAYLOAD_SIZE) {
        idx = -EINVAL;
        goto free_dup_buf;
    }
    
    //IOSimpleLockLock(txq->lock);
    
    if (iwl_queue_space(txq) < ((cmd->flags & CMD_ASYNC) ? 2 : 1)) {
        //IOSimpleLockUnlock(txq->lock);
        
        IWL_ERR(trans, "No space in command queue\n");
        // TODO: Implement
        //iwl_op_mode_cmd_queue_full(trans->op_mode);
        idx = -ENOSPC;
        goto free_dup_buf;
    }
    
    idx = iwl_pcie_get_cmd_index(txq, txq->write_ptr);
    out_cmd = txq->entries[idx].cmd;
    out_meta = &txq->entries[idx].meta;
    
    memset(out_meta, 0, sizeof(*out_meta));    /* re-initialize to NULL */
    if (cmd->flags & CMD_WANT_SKB)
        out_meta->source = cmd;
    
    /* set up the header */
    if (group_id != 0) {
        out_cmd->hdr_wide.cmd = iwl_cmd_opcode(cmd->id);
        out_cmd->hdr_wide.group_id = group_id;
        out_cmd->hdr_wide.version = iwl_cmd_version(cmd->id);
        out_cmd->hdr_wide.length = cpu_to_le16(cmd_size - sizeof(struct iwl_cmd_header_wide));
        out_cmd->hdr_wide.reserved = 0;
        out_cmd->hdr_wide.sequence = cpu_to_le16(QUEUE_TO_SEQ(trans_pcie->cmd_queue) | INDEX_TO_SEQ(txq->write_ptr));
        
        cmd_pos = sizeof(struct iwl_cmd_header_wide);
        copy_size = sizeof(struct iwl_cmd_header_wide);
    } else {
        out_cmd->hdr.cmd = iwl_cmd_opcode(cmd->id);
        out_cmd->hdr.sequence = cpu_to_le16(QUEUE_TO_SEQ(trans_pcie->cmd_queue) | INDEX_TO_SEQ(txq->write_ptr));
        out_cmd->hdr.group_id = 0;
        
        cmd_pos = sizeof(struct iwl_cmd_header);
        copy_size = sizeof(struct iwl_cmd_header);
    }
    
    /* and copy the data that needs to be copied */
    for (i = 0; i < IWL_MAX_CMD_TBS_PER_TFD; i++) {
        int copy;
        
        if (!cmd->len[i])
            continue;
        
        /* copy everything if not nocopy/dup */
        if (!(cmd->dataflags[i] & (IWL_HCMD_DFL_NOCOPY | IWL_HCMD_DFL_DUP))) {
            copy = cmd->len[i];
            
            memcpy((u8 *)out_cmd + cmd_pos, cmd->data[i], copy);
            cmd_pos += copy;
            copy_size += copy;
            continue;
        }
        
        /*
         * Otherwise we need at least IWL_FIRST_TB_SIZE copied
         * in total (for bi-directional DMA), but copy up to what
         * we can fit into the payload for debug dump purposes.
         */
        copy = min_t(int, TFD_MAX_PAYLOAD_SIZE - cmd_pos, cmd->len[i]);
        
        memcpy((u8 *)out_cmd + cmd_pos, cmd->data[i], copy);
        cmd_pos += copy;
        
        /* However, treat copy_size the proper way, we need it below */
        if (copy_size < IWL_FIRST_TB_SIZE) {
            copy = IWL_FIRST_TB_SIZE - copy_size;
            
            if (copy > cmd->len[i])
                copy = cmd->len[i];
            copy_size += copy;
        }
    }
    
    IWL_DEBUG_HC(trans,
                 "Sending command %s (%.2x.%.2x), seq: 0x%04X, %d bytes at %d[%d]:%d\n",
                 iwl_get_cmd_string(trans, cmd->id),
                 group_id, out_cmd->hdr.cmd,
                 le16_to_cpu(out_cmd->hdr.sequence),
                 cmd_size, txq->write_ptr, idx, trans_pcie->cmd_queue);
    
    /* start the TFD with the minimum copy bytes */
    tb0_size = min_t(int, copy_size, IWL_FIRST_TB_SIZE);
    memcpy(&txq->first_tb_bufs[idx], &out_cmd->hdr, tb0_size);
    iwl_pcie_txq_build_tfd(trans, txq, iwl_pcie_get_first_tb_dma(txq, idx), tb0_size, true);
    
    /* map first command fragment, if any remains */
    if (copy_size > tb0_size) {
        struct iwl_dma_ptr *dma = allocate_dma_buf(copy_size - tb0_size, DMA_BIT_MASK(trans_pcie->addr_size));
        if (!dma) {
            iwl_pcie_tfd_unmap(trans, out_meta, txq, txq->write_ptr);
            idx = -ENOMEM;
            goto out;
        }
        out_meta->dma[0] = dma;
        memcpy(dma->addr, ((u8 *)&out_cmd->hdr) + tb0_size, copy_size - tb0_size);
        iwl_pcie_txq_build_tfd(trans, txq, dma->dma, copy_size - tb0_size, false);
    }
    
    /* map the remaining (adjusted) nocopy/dup fragments */
    for (i = 0; i < IWL_MAX_CMD_TBS_PER_TFD; i++) {
        const void *data = cmddata[i];
        
        if (!cmdlen[i])
            continue;
        if (!(cmd->dataflags[i] & (IWL_HCMD_DFL_NOCOPY | IWL_HCMD_DFL_DUP)))
            continue;
        if (cmd->dataflags[i] & IWL_HCMD_DFL_DUP)
            data = dup_buf;
        
        struct iwl_dma_ptr *dma = allocate_dma_buf(cmdlen[i], DMA_BIT_MASK(trans_pcie->addr_size));
        if (!dma) {
            iwl_pcie_tfd_unmap(trans, out_meta, txq, txq->write_ptr);
            idx = -ENOMEM;
            goto out;
        }
        out_meta->dma[i + 1] = dma;
        memcpy(dma->addr, data, cmdlen[i]);
        iwl_pcie_txq_build_tfd(trans, txq, dma->dma, cmdlen[i], false);
    }
    
    BUILD_BUG_ON(IWL_TFH_NUM_TBS > sizeof(out_meta->tbs) * BITS_PER_BYTE);
    out_meta->flags = cmd->flags;
    if (txq->entries[idx].free_buf) {
        IWL_DEBUG_TX(trans, "txq->entries[%d].free_buf is not null", idx);
        IOFree((void *)txq->entries[idx].free_buf, txq->entries[idx].free_buf_size);
    }
    
    txq->entries[idx].free_buf = dup_buf;
    txq->entries[idx].free_buf_size = dup_buf_size;
    
    //trace_iwlwifi_dev_hcmd(trans->dev, cmd, cmd_size, &out_cmd->hdr_wide);
    
    /* start timer if queue currently empty */
    if (txq->read_ptr == txq->write_ptr && txq->wd_timeout) {
        // TODO: Implement
        // mod_timer(&txq->stuck_timer, jiffies + txq->wd_timeout);
    }

    flags = IOSimpleLockLockDisableInterrupt(trans_pcie->reg_lock);
    
    ret = iwl_pcie_set_cmd_in_flight(trans, cmd);
    if (ret < 0) {
        idx = ret;
        IOSimpleLockUnlockEnableInterrupt(trans_pcie->reg_lock, flags);
        goto out;
    }
    
    /* Increment and update queue's write index */
    txq->write_ptr = iwl_queue_inc_wrap(txq->write_ptr);
    iwl_pcie_txq_inc_wr_ptr(trans, txq);
    
    IOSimpleLockUnlockEnableInterrupt(trans_pcie->reg_lock, flags);
    
out:
    //IOSimpleLockUnlock(txq->lock);
free_dup_buf:
//    if (idx < 0)
//        kfree(dup_buf);
    return idx;
}

// line 1810
static int iwl_pcie_send_hcmd_async(struct iwl_trans *trans, struct iwl_host_cmd *cmd)
{
    int ret;
    
    /* An asynchronous command can not expect an SKB to be set. */
    if (WARN_ON(cmd->flags & CMD_WANT_SKB))
        return -EINVAL;
    
    ret = iwl_pcie_enqueue_hcmd(trans, cmd);
    if (ret < 0) {
        IWL_ERR(trans, "Error sending %s: enqueue_hcmd failed: %d\n", iwl_get_cmd_string(trans, cmd->id), ret);
        return ret;
    }
    return 0;
}

/* line 1723
 * iwl_pcie_hcmd_complete - Pull unused buffers off the queue and reclaim them
 * @rxb: Rx buffer to reclaim
 */
void IntelWifi::iwl_pcie_hcmd_complete(struct iwl_trans *trans,
                            struct iwl_rx_cmd_buffer *rxb)
{
    struct iwl_rx_packet *pkt = (struct iwl_rx_packet *)rxb_addr(rxb);
    u16 sequence = le16_to_cpu(pkt->hdr.sequence);
    u8 group_id;
    u32 cmd_id;
    int txq_id = SEQ_TO_QUEUE(sequence);
    int index = SEQ_TO_INDEX(sequence);
    int cmd_index;
    struct iwl_device_cmd *cmd;
    struct iwl_cmd_meta *meta;
    struct iwl_trans_pcie *trans_pcie = IWL_TRANS_GET_PCIE_TRANS(trans);
    struct iwl_txq *txq = trans_pcie->txq[trans_pcie->cmd_queue];
    
    /* If a Tx command is being handled and it isn't in the actual
     * command queue then there a command routing bug has been introduced
     * in the queue management code. */
    if (txq_id != trans_pcie->cmd_queue) {
        IWL_ERR(trans, "wrong command queue %d (should be %d), sequence 0x%X readp=%d writep=%d\n",
                txq_id, trans_pcie->cmd_queue, sequence, txq->read_ptr, txq->write_ptr);
        //iwl_print_hex_error(trans, pkt, 32);
        return;
    }
    
    //spin_lock_bh(&txq->lock);
    //IOSimpleLockLock(txq->lock);
    
    cmd_index = iwl_pcie_get_cmd_index(txq, index);
    cmd = txq->entries[cmd_index].cmd;
    meta = &txq->entries[cmd_index].meta;
    group_id = cmd->hdr.group_id;
    cmd_id = iwl_cmd_id(cmd->hdr.cmd, group_id, 0);
    
    iwl_pcie_tfd_unmap(trans, meta, txq, index);
    
    /* Input error checking is done when commands are added to queue. */
    if (meta->flags & CMD_WANT_SKB) {
        void *p = rxb_steal_page(rxb);
        
        meta->source->resp_pkt = pkt;
        meta->source->_rx_page_addr = (unsigned long)p;
        meta->source->_rx_page_order = trans_pcie->rx_page_order;
    }
    
    if (meta->flags & CMD_WANT_ASYNC_CALLBACK)
        iwl_op_mode_async_cb(trans->op_mode, cmd);
    
    iwl_pcie_cmdq_reclaim(trans, txq_id, index);
    
    if (!(meta->flags & CMD_ASYNC)) {
        if (!test_bit(STATUS_SYNC_HCMD_ACTIVE, &trans->status)) {
            IWL_WARN(trans, "HCMD_ACTIVE already clear for command %s\n", iwl_get_cmd_string(trans, cmd_id));
        }
        clear_bit(STATUS_SYNC_HCMD_ACTIVE, &trans->status);
        IWL_DEBUG_INFO(trans, "Clearing HCMD_ACTIVE for command %s\n", iwl_get_cmd_string(trans, cmd_id));

        IOLockLock(trans_pcie->wait_command_queue);
        IOLockWakeup(trans_pcie->wait_command_queue, &trans->status, true);
        IOLockUnlock(trans_pcie->wait_command_queue);
    }
    
    if (meta->flags & CMD_MAKE_TRANS_IDLE) {
        IWL_DEBUG_INFO(trans, "complete %s - mark trans as idle\n", iwl_get_cmd_string(trans, cmd->hdr.cmd));
        set_bit(STATUS_TRANS_IDLE, &trans->status);
        //wake_up(&trans_pcie->d0i3_waitq);
    }
    
    if (meta->flags & CMD_WAKE_UP_TRANS) {
        IWL_DEBUG_INFO(trans, "complete %s - clear trans idle flag\n", iwl_get_cmd_string(trans, cmd->hdr.cmd));
        clear_bit(STATUS_TRANS_IDLE, &trans->status);
        //wake_up(&trans_pcie->d0i3_waitq);
    }
    
    meta->flags = 0;
    
    //spin_unlock_bh(&txq->lock);
    //IOSimpleLockUnlock(txq->lock);
}


#define HOST_COMPLETE_TIMEOUT 2000

// line 1829
static int iwl_pcie_send_hcmd_sync(struct iwl_trans *trans, struct iwl_host_cmd *cmd)
{
    struct iwl_trans_pcie *trans_pcie = IWL_TRANS_GET_PCIE_TRANS(trans);
    struct iwl_txq *txq = trans_pcie->txq[trans_pcie->cmd_queue];
    int cmd_idx;
    int ret;
    
    IWL_DEBUG_INFO(trans, "Attempting to send sync command %s\n", iwl_get_cmd_string(trans, cmd->id));
    
    if (test_and_set_bit(STATUS_SYNC_HCMD_ACTIVE, &trans->status))
        return -EIO;
    
    IWL_DEBUG_INFO(trans, "Setting HCMD_ACTIVE for command %s\n", iwl_get_cmd_string(trans, cmd->id));
    
//    if (pm_runtime_suspended(&trans_pcie->pci_dev->dev)) {
//        ret = wait_event_timeout(trans_pcie->d0i3_waitq,
//                                 pm_runtime_active(&trans_pcie->pci_dev->dev),
//                                 msecs_to_jiffies(IWL_TRANS_IDLE_TIMEOUT));
//        if (!ret) {
//            IWL_ERR(trans, "Timeout exiting D0i3 before hcmd\n");
//            return -ETIMEDOUT;
//        }
//    }
    
    cmd_idx = iwl_pcie_enqueue_hcmd(trans, cmd);
    if (cmd_idx < 0) {
        ret = cmd_idx;
        clear_bit(STATUS_SYNC_HCMD_ACTIVE, &trans->status);
        IWL_ERR(trans, "Error sending %s: enqueue_hcmd failed: %d\n", iwl_get_cmd_string(trans, cmd->id), ret);
        return ret;
    }
    
    IOLockLock(trans_pcie->wait_command_queue);
    AbsoluteTime deadline;
    clock_interval_to_deadline(HOST_COMPLETE_TIMEOUT * 2, kMillisecondScale, (UInt64 *) &deadline);
    ret = IOLockSleepDeadline(trans_pcie->wait_command_queue, &trans->status, deadline, THREAD_INTERRUPTIBLE);
    IOLockUnlock(trans_pcie->wait_command_queue);
    
    if (ret != THREAD_AWAKENED) {
        IWL_ERR(trans, "Error sending %s: time out after %dms.\n", iwl_get_cmd_string(trans, cmd->id),
                HOST_COMPLETE_TIMEOUT);

        IWL_ERR(trans, "Current CMD queue read_ptr %d write_ptr %d\n", txq->read_ptr, txq->write_ptr);

        clear_bit(STATUS_SYNC_HCMD_ACTIVE, &trans->status);
        IWL_DEBUG_INFO(trans, "Clearing HCMD_ACTIVE for command %s\n", iwl_get_cmd_string(trans, cmd->id));
        ret = -ETIMEDOUT;

        iwl_force_nmi(trans);
        // TODO: Implement
        // iwl_trans_fw_error(trans);

        goto cancel;
    }
    
    if (test_bit(STATUS_FW_ERROR, &trans->status)) {
        IWL_ERR(trans, "FW error in SYNC CMD %s\n",
                iwl_get_cmd_string(trans, cmd->id));
        //dump_stack();
        ret = -EIO;
        goto cancel;
    }
    
    if (!(cmd->flags & CMD_SEND_IN_RFKILL) &&
        test_bit(STATUS_RFKILL_OPMODE, &trans->status)) {
        IWL_DEBUG_RF_KILL(trans, "RFKILL in SYNC CMD... no rsp\n");
        ret = -ERFKILL;
        goto cancel;
    }
    
    if ((cmd->flags & CMD_WANT_SKB) && !cmd->resp_pkt) {
        IWL_ERR(trans, "Error: Response NULL in '%s'\n",
                iwl_get_cmd_string(trans, cmd->id));
        ret = -EIO;
        goto cancel;
    }
    
    return 0;
    
cancel:
    if (cmd->flags & CMD_WANT_SKB) {
        /*
         * Cancel the CMD_WANT_SKB flag for the cmd in the
         * TX cmd queue. Otherwise in case the cmd comes
         * in later, it will possibly set an invalid
         * address (cmd->meta.source).
         */
        txq->entries[cmd_idx].meta.flags &= ~CMD_WANT_SKB;
    }
    
    if (cmd->resp_pkt) {
        iwl_free_resp(cmd);
        cmd->resp_pkt = NULL;
    }
    
    return ret;
}



// line 1935
int iwl_trans_pcie_send_hcmd(struct iwl_trans *trans, struct iwl_host_cmd *cmd)
{
    if (!(cmd->flags & CMD_SEND_IN_RFKILL) && test_bit(STATUS_RFKILL_OPMODE, &trans->status)) {
        IWL_DEBUG_RF_KILL(trans, "Dropping CMD 0x%x: RF KILL\n", cmd->id);
        return -ERFKILL;
    }
    
    if (cmd->flags & CMD_ASYNC)
        return iwl_pcie_send_hcmd_async(trans, cmd);
    
    /* We still can fail on RFKILL that can be asserted while we wait */
    return iwl_pcie_send_hcmd_sync(trans, cmd);
}



// line 2256
int iwl_trans_pcie_tx(struct iwl_trans *trans, struct sk_buff *skb,
                      struct iwl_device_cmd *dev_cmd, int txq_id)
{
    // TODO: Implement...
    
    return 0;
    
//    mbuf_t mb;
//    
//    
//    struct iwl_trans_pcie *trans_pcie = IWL_TRANS_GET_PCIE_TRANS(trans);
////    struct ieee80211_hdr *hdr;
//    struct iwl_tx_cmd *tx_cmd = (struct iwl_tx_cmd *)dev_cmd->payload;
//    struct iwl_cmd_meta *out_meta;
//    struct iwl_txq *txq;
//    dma_addr_t tb0_phys, tb1_phys, scratch_phys;
//    void *tb1_addr;
//    void *tfd;
//    u16 len, tb1_len;
//    bool wait_write_ptr;
//    __le16 fc;
//    u8 hdr_len;
//    u16 wifi_seq;
//    bool amsdu;
//    
//    txq = trans_pcie->txq[txq_id];
//
//    if (!test_bit(txq_id, trans_pcie->queue_used))
//        return -EINVAL;

//    if (unlikely(trans_pcie->sw_csum_tx && skb->ip_summed == CHECKSUM_PARTIAL)) {
//        int offs = skb_checksum_start_offset(skb);
//        int csum_offs = offs + skb->csum_offset;
//        __wsum csum;
//
//        if (skb_ensure_writable(skb, csum_offs + sizeof(__sum16)))
//            return -1;
//
//        csum = skb_checksum(skb, offs, skb->len - offs, 0);
//        *(__sum16 *)(skb->data + csum_offs) = csum_fold(csum);
//
//        skb->ip_summed = CHECKSUM_UNNECESSARY;
//    }

//    if (skb_is_nonlinear(skb) &&
//        skb_shinfo(skb)->nr_frags > IWL_PCIE_MAX_FRAGS(trans_pcie) &&
//        __skb_linearize(skb))
//        return -ENOMEM;
//
    /* mac80211 always puts the full header into the SKB's head,
     * so there's no need to check if it's readable there
     */
    
//    hdr = (struct ieee80211_hdr *)skb->data;
//    fc = hdr->frame_control;
//    hdr_len = ieee80211_hdrlen(fc);
//
//    spin_lock(&txq->lock);
//
//    if (iwl_queue_space(txq) < txq->high_mark) {
//        iwl_stop_queue(trans, txq);
//
//        /* don't put the packet on the ring, if there is no room */
//        if (unlikely(iwl_queue_space(txq) < 3)) {
//            struct iwl_device_cmd **dev_cmd_ptr;
//
//            dev_cmd_ptr = (void *)((u8 *)skb->cb +
//                                   trans_pcie->dev_cmd_offs);
//
//            *dev_cmd_ptr = dev_cmd;
//            __skb_queue_tail(&txq->overflow_q, skb);
//
//            spin_unlock(&txq->lock);
//            return 0;
//        }
//    }

//    /* In AGG mode, the index in the ring must correspond to the WiFi
//     * sequence number. This is a HW requirements to help the SCD to parse
//     * the BA.
//     * Check here that the packets are in the right place on the ring.
//     */
//    wifi_seq = IEEE80211_SEQ_TO_SN(le16_to_cpu(hdr->seq_ctrl));
//    WARN_ONCE(txq->ampdu &&
//              (wifi_seq & 0xff) != txq->write_ptr,
//              "Q: %d WiFi Seq %d tfdNum %d",
//              txq_id, wifi_seq, txq->write_ptr);
//
//    /* Set up driver data for this TFD */
//    txq->entries[txq->write_ptr].skb = skb;
//    txq->entries[txq->write_ptr].cmd = dev_cmd;
//
//    dev_cmd->hdr.sequence =
//    cpu_to_le16((u16)(QUEUE_TO_SEQ(txq_id) |
//                      INDEX_TO_SEQ(txq->write_ptr)));
//
//    tb0_phys = iwl_pcie_get_first_tb_dma(txq, txq->write_ptr);
//    scratch_phys = tb0_phys + sizeof(struct iwl_cmd_header) +
//    offsetof(struct iwl_tx_cmd, scratch);
//
//    tx_cmd->dram_lsb_ptr = cpu_to_le32(scratch_phys);
//    tx_cmd->dram_msb_ptr = iwl_get_dma_hi_addr(scratch_phys);
//
//    /* Set up first empty entry in queue's array of Tx/cmd buffers */
//    out_meta = &txq->entries[txq->write_ptr].meta;
//    out_meta->flags = 0;
//
//    /*
//     * The second TB (tb1) points to the remainder of the TX command
//     * and the 802.11 header - dword aligned size
//     * (This calculation modifies the TX command, so do it before the
//     * setup of the first TB)
//     */
//    len = sizeof(struct iwl_tx_cmd) + sizeof(struct iwl_cmd_header) +
//    hdr_len - IWL_FIRST_TB_SIZE;
//    /* do not align A-MSDU to dword as the subframe header aligns it */
//    amsdu = ieee80211_is_data_qos(fc) &&
//    (*ieee80211_get_qos_ctl(hdr) &
//     IEEE80211_QOS_CTL_A_MSDU_PRESENT);
//    if (trans_pcie->sw_csum_tx || !amsdu) {
//        tb1_len = ALIGN(len, 4);
//        /* Tell NIC about any 2-byte padding after MAC header */
//        if (tb1_len != len)
//            tx_cmd->tx_flags |= cpu_to_le32(TX_CMD_FLG_MH_PAD);
//    } else {
//        tb1_len = len;
//    }
//
//    /*
//     * The first TB points to bi-directional DMA data, we'll
//     * memcpy the data into it later.
//     */
//    iwl_pcie_txq_build_tfd(trans, txq, tb0_phys,
//                           IWL_FIRST_TB_SIZE, true);
//
//    /* there must be data left over for TB1 or this code must be changed */
//    BUILD_BUG_ON(sizeof(struct iwl_tx_cmd) < IWL_FIRST_TB_SIZE);
//
//    /* map the data for TB1 */
//    tb1_addr = ((u8 *)&dev_cmd->hdr) + IWL_FIRST_TB_SIZE;
//    tb1_phys = dma_map_single(trans->dev, tb1_addr, tb1_len, DMA_TO_DEVICE);
//    if (unlikely(dma_mapping_error(trans->dev, tb1_phys)))
//        goto out_err;
//    iwl_pcie_txq_build_tfd(trans, txq, tb1_phys, tb1_len, false);
//
//    if (amsdu) {
//        if (unlikely(iwl_fill_data_tbs_amsdu(trans, skb, txq, hdr_len,
//                                             out_meta, dev_cmd,
//                                             tb1_len)))
//            goto out_err;
//    } else if (unlikely(iwl_fill_data_tbs(trans, skb, txq, hdr_len,
//                                          out_meta, dev_cmd, tb1_len))) {
//        goto out_err;
//    }
//
//    /* building the A-MSDU might have changed this data, so memcpy it now */
//    memcpy(&txq->first_tb_bufs[txq->write_ptr], &dev_cmd->hdr,
//           IWL_FIRST_TB_SIZE);
//
//    tfd = iwl_pcie_get_tfd(trans_pcie, txq, txq->write_ptr);
//    /* Set up entry for this TFD in Tx byte-count array */
//    iwl_pcie_txq_update_byte_cnt_tbl(trans, txq, le16_to_cpu(tx_cmd->len),
//                                     iwl_pcie_tfd_get_num_tbs(trans, tfd));
//
//    wait_write_ptr = ieee80211_has_morefrags(fc);
//
//    /* start timer if queue currently empty */
//    if (txq->read_ptr == txq->write_ptr) {
//        if (txq->wd_timeout) {
//            /*
//             * If the TXQ is active, then set the timer, if not,
//             * set the timer in remainder so that the timer will
//             * be armed with the right value when the station will
//             * wake up.
//             */
//            if (!txq->frozen)
//                mod_timer(&txq->stuck_timer,
//                          jiffies + txq->wd_timeout);
//            else
//                txq->frozen_expiry_remainder = txq->wd_timeout;
//        }
//        IWL_DEBUG_RPM(trans, "Q: %d first tx - take ref\n", txq->id);
//        iwl_trans_ref(trans);
//    }
//
//    /* Tell device the write index *just past* this latest filled TFD */
//    txq->write_ptr = iwl_queue_inc_wrap(txq->write_ptr);
//    if (!wait_write_ptr)
//        iwl_pcie_txq_inc_wr_ptr(trans, txq);
//
//    /*
//     * At this point the frame is "transmitted" successfully
//     * and we will get a TX status notification eventually.
//     */
//    spin_unlock(&txq->lock);
//    return 0;
//out_err:
//    spin_unlock(&txq->lock);
//    return -1;
}




