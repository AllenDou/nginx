
/****************************************************************************/
/* PKP Register Offsets                                                     */
/****************************************************************************/
/* define register offsets here */


#define BAR_0                   0x10
#define BAR_1                   0x18
#define BAR_2                   0x20
#define BAR_3                   0x28

#define PCI_CONFIG_04           0x04
#define PCI_CONFIG_58           0X58
#define PCI_CONFIG_4C           0x4C
#define PCI_CACHE_LINE          0x0C
#define PCIX_SPLIT_TRANSACTION  0xE0
#ifndef PCI_INTERRUPT_LINE
#define PCI_INTERRUPT_LINE      0x3C
#endif

#define NPX_DEVICE            0x0010
#define N3_DEVICE             0x0011
#define CN15XX                    15
#define CN16XX                    16

extern Uint32  csrbase_a_offset;
extern Uint32  csrbase_b_offset;


#define NITROX_PX_MAX_GROUPS       4

#define CSRBASE_A                   csrbase_a 
#define CSRBASE_B                   csrbase_b
#define BASE_A_OFFSET               csrbase_a_offset
#define BASE_B_OFFSET               csrbase_b_offset

/*BAR 0*/
#define COMMAND_STATUS               (BASE_A_OFFSET + 0x00)
#define UNIT_ENABLE                  (BASE_A_OFFSET + 0x10)
#define IMR_REG                      (BASE_A_OFFSET + 0x20)
#define ISR_REG                      (BASE_A_OFFSET + 0x28)
#define FAILING_SEQ_REG              (BASE_A_OFFSET + 0x30)
#define FAILING_EXEC_REG             (BASE_A_OFFSET + 0x38)
#define ECH_STAT_COUNTER_HIGH_REG    (BASE_A_OFFSET + 0x88)
#define ECH_STAT_COUNTER_LOW_REG     (BASE_A_OFFSET + 0x90)
#define EPC_STAT_COUNTER_HIGH_REG    (BASE_A_OFFSET + 0x98)
#define EPC_STAT_COUNTER_LOW_REG     (BASE_A_OFFSET + 0xA0)
#define PMLT_STAT_COUNTER_LOW_REG    (BASE_A_OFFSET + 0xA8)
#define PMLT_STAT_COUNTER_HIGH_REG   (BASE_A_OFFSET + 0xB0)


#define CLK_STAT_COUNTER_HIGH_REG    (BASE_A_OFFSET + 0xB8)
#define CLK_STAT_COUNTER_LOW_REG     (BASE_A_OFFSET + 0xC0)
#define PCI_ERR_REG                  (BASE_A_OFFSET + 0xD0)
#define DEBUG_REG                    (BASE_A_OFFSET + 0x68)
#define CMC_CTL_REG                  (BASE_A_OFFSET + 0xD8)
#define UCODE_LOAD                   (BASE_A_OFFSET + 0x18)
#define PSE_TO_HOST_DATA             (BASE_A_OFFSET + 0x58)
#define HOST_TO_PSE_DATA             (BASE_A_OFFSET + 0x60)

#ifdef INTERRUPT_COALESCING
#define GENINT_COUNT_THOLD_REG       (BASE_A_OFFSET + 0x280)
#define GENINT_COUNT_INT_TIME_REG    (BASE_A_OFFSET + 0x288)
#define GENINT_COUNT_REG             (BASE_A_OFFSET + 0x290)
#define GENINT_COUNT_TIME_REG        (BASE_A_OFFSET + 0x298)
#define GENINT_COUNT_SUB_REG         (BASE_A_OFFSET + 0x2A0)
#endif
#define REG_EXEC_GROUP		     (BASE_A_OFFSET + 0x2A8)
#define EPC_EFUS_RCMD		     (BASE_A_OFFSET + 0x300)
#define EPC_EFUS_SPR_REPAIR_SUM	     (BASE_A_OFFSET + 0x320)
#define EPC_EFUS_SPR_REPAIR_RES0     (BASE_A_OFFSET + 0x328)
#define EPC_EFUS_SPR_REPAIR_RES1     (BASE_A_OFFSET + 0x330)
#define EPC_EFUS_SPR_REPAIR_RES2     (BASE_A_OFFSET + 0x338)
#define EPC_ADDR_INDEX		     (BASE_A_OFFSET + 0x348)
#define EPC_EFUS_CORE_EN	     (BASE_A_OFFSET + 0x350)
#define EPC_EFUS_CHIPID		     (BASE_A_OFFSET + 0x358)
#define PCIE_CTL           	     (BASE_A_OFFSET + 0x400)
#define PCIE_INT_SUM           	     (BASE_A_OFFSET + 0x408)
#define PCIE_INT_ENB           	     (BASE_A_OFFSET + 0x410)
#define PCIE_TO_STATUS               (BASE_A_OFFSET + 0x418)
#define PCIE_CPL_ERR_STATUS1         (BASE_A_OFFSET + 0x420)
#define PCIE_CPL_ERR_STATUS2         (BASE_A_OFFSET + 0x428)
#define PCIE_CPL_ERR_STATUS3         (BASE_A_OFFSET + 0x430)
#define PCIE_BIST_STATUS             (BASE_A_OFFSET + 0x438)


/*BAR 1*/
#define  REQ0_BASE_HIGH              (BASE_B_OFFSET + 0x00)
#define  REQ0_BASE_LOW               (BASE_B_OFFSET + 0x08)
#define  REQ0_SIZE                   (BASE_B_OFFSET + 0x10)

#define  REQ1_BASE_HIGH              (BASE_B_OFFSET + 0x20)
#define  REQ1_BASE_LOW               (BASE_B_OFFSET + 0x28)
#define  REQ1_SIZE                   (BASE_B_OFFSET + 0x30)

#define  REQ2_BASE_HIGH              (BASE_B_OFFSET + 0x40)
#define  REQ2_BASE_LOW               (BASE_B_OFFSET + 0x48)
#define  REQ2_SIZE                   (BASE_B_OFFSET + 0x50)

#define  REQ3_BASE_HIGH              (BASE_B_OFFSET + 0x60)
#define  REQ3_BASE_LOW               (BASE_B_OFFSET + 0x68)
#define  REQ3_SIZE                   (BASE_B_OFFSET + 0x70)

#define REQ0_DOOR_BELL               (BASE_B_OFFSET + 0x18)
#define REQ1_DOOR_BELL               (BASE_B_OFFSET + 0x38)
#define REQ2_DOOR_BELL               (BASE_B_OFFSET + 0x58)
#define REQ3_DOOR_BELL               (BASE_B_OFFSET + 0x78)


#define REQ0_NEXT_ADDR_HIGH           (BASE_B_OFFSET + 0x100)
#define REQ1_NEXT_ADDR_HIGH           (BASE_B_OFFSET + 0x110)
#define REQ2_NEXT_ADDR_HIGH           (BASE_B_OFFSET + 0x120)
#define REQ3_NEXT_ADDR_HIGH           (BASE_B_OFFSET + 0x130)

#define REQ0_NEXT_ADDR_LOW           (BASE_B_OFFSET + 0x108)
#define REQ1_NEXT_ADDR_LOW           (BASE_B_OFFSET + 0x118)
#define REQ2_NEXT_ADDR_LOW           (BASE_B_OFFSET + 0x128)
#define REQ3_NEXT_ADDR_LOW           (BASE_B_OFFSET + 0x138)

#define REG_EXEC_GROUP               (BASE_A_OFFSET + 0x2A8)


/*LDT specific registers */
#define LMT_CONTROL_REG               0xC0
#define LMT_INTERRUPT_CONTROL_REG      0xC8
#define LMT_INTERRUPT_DESTINATION_REG   0xD0
#define LMT_ERROR_REG               0xD8
#define LMT_EXPECTED_CRC_REG         0xE0
#define LMT_RCVD_CRC_REG            0xE8

#define MAX_N1_QUEUES         4

