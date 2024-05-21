#define MAX_STRING_SIZE 40

typedef signed char epicsInt8;
typedef unsigned char epicsUInt8;
typedef short epicsInt16;
typedef unsigned short epicsUInt16;
typedef int epicsInt32;
typedef unsigned int epicsUInt32;
typedef long long epicsInt64;
typedef unsigned long long epicsUInt64;

typedef epicsUInt16 epicsEnum16;
typedef float epicsFloat32;
typedef double epicsFloat64;
typedef epicsInt32 epicsStatus;

typedef struct epicsMutexParm *epicsMutexId;

struct macro_link
{
    char *macroStr;
};

struct json_link
{
    char *string;
    struct jlink *jlink;
};

typedef long (*LINKCVT)();

/* structure of a VME io channel */
struct vmeio
{
    short card;
    short signal;
    char *parm;
};

/* structure of a CAMAC io channel */
struct camacio
{
    short b;
    short c;
    short n;
    short a;
    short f;
    char *parm;
};

/* structure of a RF io channel */
struct rfio
{
    short branch;
    short cryo;
    short micro;
    short dataset;
    short element;
    long ext;
};

/* structure of a Allen-Bradley io channel */
struct abio
{
    short link;
    short adapter;
    short card;
    short signal;
    char *parm;
};

/* structure of a gpib io channel */
struct gpibio
{
    short link;
    short addr; /* device address */
    char *parm;
};

/* structure of a bitbus io channel */
struct bitbusio
{
    unsigned char link;
    unsigned char node;
    unsigned char port;
    unsigned char signal;
    char *parm;
};

/* structure of a bitbus to gpib io channel */
struct bbgpibio
{
    unsigned char link;
    unsigned char bbaddr;
    unsigned char gpibaddr;
    unsigned char pad;
    char *parm;
};

/* structure of an instrument io link */
struct instio
{
    char *string;
};

/* structure of a vxi link */
struct vxiio
{
    short flag; /* 0 = frame/slot, 1 = SA */
    short frame;
    short slot;
    short la; /* logical address if flag =1 */
    short signal;
    char *parm;
};

typedef struct epicsTimeStamp
{
    epicsUInt32 secPastEpoch; /**< \brief seconds since 0000 Jan 1, 1990 */
    epicsUInt32 nsec;         /**< \brief nanoseconds within second */
} epicsTimeStamp;

typedef struct ELLNODE
{
    struct ELLNODE *next;     /**< \brief Pointer to next node in list */
    struct ELLNODE *previous; /**< \brief Pointer to previous node in list */
} ELLNODE;

typedef struct ELLLIST
{
    ELLNODE node; /**< \brief Pointers to the first and last nodes on list */
    int count;    /**< \brief Number of nodes on the list */
} ELLLIST;

struct pv_link
{
    ELLNODE backlinknode;
    char *pvname;         /* pvname link points to */
    void *pvt;            /* CA or DB private */
    LINKCVT getCvt;       /* input conversion function */
    short pvlMask;        /* Options mask */
    short lastGetdbrType; /* last dbrType for DB or CA get */
};

union value
{
    char *constantStr;            /*constant string*/
    struct macro_link macro_link; /* link containing macro substitution*/
    struct json_link json;        /* JSON-encoded link */
    struct pv_link pv_link;       /* link to process variable*/
    struct vmeio vmeio;           /* vme io point */
    struct camacio camacio;       /* camac io point */
    struct rfio rfio;             /* CEBAF RF buffer interface */
    struct abio abio;             /* Allen-Bradley io point */
    struct gpibio gpibio;
    struct bitbusio bitbusio;
    struct instio instio;     /* instrument io link */
    struct bbgpibio bbgpibio; /* bitbus to gpib io link */
    struct vxiio vxiio;       /* vxi io */
};

struct link
{
    struct dbCommon *precord; /* Pointer to record owning link */
    short type;
    short flags;
    struct lset *lset;
    char *text; /* Raw link text */
    union value value;
};

typedef long (*dbLinkUserCallback)(struct link *plink, void *priv);
typedef epicsUInt64 epicsUTag;

typedef struct lset
{
    const unsigned isConstant : 1;
    const unsigned isVolatile : 1;
    void (*openLink)(struct link *plink);
    void (*removeLink)(void *locker, struct link *plink);
    long (*loadScalar)(struct link *plink, short dbrType, void *pbuffer);
    long (*loadLS)(struct link *plink, char *pbuffer, epicsUInt32 size,
                   epicsUInt32 *plen);
    long (*loadArray)(struct link *plink, short dbrType, void *pbuffer,
                      long *pnRequest);
    int (*isConnected)(const struct link *plink);
    int (*getDBFtype)(const struct link *plink);
    long (*getElements)(const struct link *plink, long *pnElements);
    long (*getValue)(struct link *plink, short dbrType, void *pbuffer,
                     long *pnRequest);
    long (*getControlLimits)(const struct link *plink, double *lo, double *hi);
    long (*getGraphicLimits)(const struct link *plink, double *lo, double *hi);
    long (*getAlarmLimits)(const struct link *plink, double *lolo, double *lo,
                           double *hi, double *hihi);
    long (*getPrecision)(const struct link *plink, short *precision);
    long (*getUnits)(const struct link *plink, char *units, int unitsSize);
    long (*getAlarm)(const struct link *plink, epicsEnum16 *status,
                     epicsEnum16 *severity);
    long (*getTimeStamp)(const struct link *plink, epicsTimeStamp *pstamp);
    long (*putValue)(struct link *plink, short dbrType,
                     const void *pbuffer, long nRequest);
    long (*putAsync)(struct link *plink, short dbrType,
                     const void *pbuffer, long nRequest);
    void (*scanForward)(struct link *plink);
    long (*doLocked)(struct link *plink, dbLinkUserCallback rtn, void *priv);
    long (*getAlarmMsg)(const struct link *plink, epicsEnum16 *status,
                        epicsEnum16 *severity, char *msgbuf, int msgbuflen);
    long (*getTimeStampTag)(const struct link *plink, epicsTimeStamp *pstamp, epicsUTag *ptag);
} lset;

typedef struct link DBLINK;

typedef long (*DEVSUPFUN)(); /* ptr to device support function*/

typedef struct dset
{                             /* device support entry table */
    long number;              /*number of support routines*/
    DEVSUPFUN report;         /*print report*/
    DEVSUPFUN init;           /*init support layer*/
    DEVSUPFUN init_record;    /*init device for particular record*/
    DEVSUPFUN get_ioint_info; /* get io interrupt information*/
    /*other functions are record dependent*/
} dset;
typedef dset unambiguous_dset;

typedef struct dbCommon
{
    char name[61];                    /**< @brief Record Name */
    char desc[41];                    /**< @brief Descriptor */
    char asg[29];                     /**< @brief Access Security Group */
    epicsEnum16 scan;                 /**< @brief Scan Mechanism */
    epicsEnum16 pini;                 /**< @brief Process at iocInit */
    epicsInt16 phas;                  /**< @brief Scan Phase */
    char evnt[40];                    /**< @brief Event Name */
    epicsInt16 tse;                   /**< @brief Time Stamp Event */
    DBLINK tsel;                      /**< @brief Time Stamp Link */
    epicsEnum16 dtyp;                 /**< @brief Device Type */
    epicsInt16 disv;                  /**< @brief Disable Value */
    epicsInt16 disa;                  /**< @brief Disable */
    DBLINK sdis;                      /**< @brief Scanning Disable */
    epicsMutexId mlok;                /**< @brief Monitor lock */
    ELLLIST mlis;                     /**< @brief Monitor List */
    ELLLIST bklnk;                    /**< @brief Backwards link tracking */
    epicsUInt8 disp;                  /**< @brief Disable putField */
    epicsUInt8 proc;                  /**< @brief Force Processing */
    epicsEnum16 stat;                 /**< @brief Alarm Status */
    epicsEnum16 sevr;                 /**< @brief Alarm Severity */
    char amsg[40];                    /**< @brief Alarm Message */
    epicsEnum16 nsta;                 /**< @brief New Alarm Status */
    epicsEnum16 nsev;                 /**< @brief New Alarm Severity */
    char namsg[40];                   /**< @brief New Alarm Message */
    epicsEnum16 acks;                 /**< @brief Alarm Ack Severity */
    epicsEnum16 ackt;                 /**< @brief Alarm Ack Transient */
    epicsEnum16 diss;                 /**< @brief Disable Alarm Sevrty */
    epicsUInt8 lcnt;                  /**< @brief Lock Count */
    epicsUInt8 pact;                  /**< @brief Record active */
    epicsUInt8 putf;                  /**< @brief dbPutField process */
    epicsUInt8 rpro;                  /**< @brief Reprocess  */
    struct asgMember *asp;            /**< @brief Access Security Pvt */
    struct processNotify *ppn;        /**< @brief pprocessNotify */
    struct processNotifyRecord *ppnr; /**< @brief pprocessNotifyRecord */
    struct scan_element *spvt;        /**< @brief Scan Private */
    struct typed_rset *rset;          /**< @brief Address of RSET */
    unambiguous_dset *dset;           /**< @brief DSET address */
    void *dpvt;                       /**< @brief Device Private */
    struct dbRecordType *rdes;        /**< @brief Address of dbRecordType */
    struct lockRecord *lset;          /**< @brief Lock Set */
    epicsEnum16 prio;                 /**< @brief Scheduling Priority */
    epicsUInt8 tpro;                  /**< @brief Trace Processing */
    epicsUInt8 bkpt;                  /**< @brief Break Point */
    epicsUInt8 udf;                   /**< @brief Undefined */
    epicsEnum16 udfs;                 /**< @brief Undefined Alarm Sevrty */
    epicsTimeStamp time;              /**< @brief Time */
    epicsUInt64 utag;                 /**< @brief Time Tag */
    DBLINK flnk;                      /**< @brief Forward Process Link */
} dbCommon;

typedef struct dbAddr
{
    struct dbCommon *precord; /* address of record                     */
    void *pfield;             /* address of field                      */
    struct dbFldDes *pfldDes; /* address of struct fldDes              */
    long no_elements;         /* number of elements (arrays)           */
    short field_type;         /* type of database field                */
    short field_size;         /* size of the field being accessed      */
    short special;            /* special processing                    */
    short dbr_field_type;     /* field type as seen by database request*/
                              /* DBR_STRING,...,DBR_ENUM,DBR_NOACCESS  */
} dbAddr;

typedef enum
{
    DBF_STRING,
    DBF_CHAR,
    DBF_UCHAR,
    DBF_SHORT,
    DBF_USHORT,
    DBF_LONG,
    DBF_ULONG,
    DBF_INT64,
    DBF_UINT64,
    DBF_FLOAT,
    DBF_DOUBLE,
    DBF_ENUM,
    DBF_MENU,
    DBF_DEVICE,
    DBF_INLINK,
    DBF_OUTLINK,
    DBF_FWDLINK,
    DBF_NOACCESS
} dbfType;

typedef enum
{
    CT_DECIMAL,
    CT_HEX
} ctType;
typedef enum
{
    ASL0,
    ASL1
} asLevel;

typedef struct dbFldDes
{                 /* field description */
    char *prompt; /*Prompt string for DCT                 */
    char *name;   /*Field name                            */
    char *extra;  /*C def for DBF_NOACCESS                */
    struct dbRecordType *pdbRecordType;
    short indRecordType;              /*within dbRecordType.papFldDes */
    short special;                    /*Special processing requirements       */
    dbfType field_type;               /*Field type as defined in dbFldTypes.h */
    unsigned int process_passive : 1; /*should dbPutField process passive   */
    unsigned int prop : 1;            /*field is a metadata, post DBE_PROPERTY on change*/
    unsigned int isDevLink : 1;       /* true for INP/OUT fields              */
    ctType base;                      /*base for integer to string conversions*/
    short promptgroup;                /*prompt, i.e. gui group                */
    short interest;                   /*interest level                        */
    asLevel as_level;                 /*access security level                 */
    char *initial;                    /*initial value                         */
    /*If (DBF_MENU,DBF_DEVICE) ftPvt is (pdbMenu,pdbDeviceMenu)             */
    void *ftPvt;
    /*On no runtime following only set for STRING                           */
    short size; /*length in bytes of a field element    */
    /*The following are only available on run time system*/
    unsigned short offset; /*Offset in bytes from beginning of record*/
} dbFldDes;

struct rset
{                          /* record support entry table */
    long number;           /*number of support routines*/
    long (*report)();      /*print report              */
    long (*init)();        /*init support              */
    long (*init_record)(); /*init record               */
    long (*process)();     /*process record            */
    long (*special)();     /*special processing        */
    long (*get_value)();   /*no longer used            */
    long (*cvt_dbaddr)();  /*cvt  dbAddr               */
    long (*get_array_info)();
    long (*put_array_info)();
    long (*get_units)();
    long (*get_precision)();
    long (*get_enum_str)();  /*get string from enum item */
    long (*get_enum_strs)(); /*get all enum strings      */
    long (*put_enum_str)();  /*put string from enum item */
    long (*get_graphic_double)();
    long (*get_control_double)();
    long (*get_alarm_double)();
};

typedef struct rset rset;

typedef struct dbRecordType
{
    ELLNODE node;
    ELLLIST attributeList; /*LIST head of attributes*/
    ELLLIST recList;       /*LIST head of sorted dbRecordNodes*/
    ELLLIST devList;       /*List of associated device support*/
    ELLLIST cdefList;      /*LIST of Cdef text items*/
    char *name;
    short no_fields;       /* number of fields defined     */
    short no_prompt;       /* number of fields to configure*/
    short no_links;        /* number of links              */
    short no_aliases;      /* number of aliases in recList */
    short *link_ind;       /* addr of array of ind in papFldDes*/
    char **papsortFldName; /* ptr to array of ptr to fld names*/
    short *sortFldInd;     /* addr of array of ind in papFldDes*/
    dbFldDes *pvalFldDes;  /*pointer dbFldDes for VAL field*/
    short indvalFlddes;    /*ind in papFldDes*/
    dbFldDes **papFldDes;  /* ptr to array of ptr to fldDes*/
    /*The following are only available on run time system*/
    rset *prset;
    int rec_size; /*record size in bytes          */
} dbRecordType;

struct dbPvd;  /* Contents private to dbPvdLib code */
struct gphPvt; /* Contents private to gpHashLib code */

typedef struct dbBase
{
    ELLLIST menuList;
    ELLLIST recordTypeList;
    ELLLIST drvList;
    ELLLIST linkList;
    ELLLIST registrarList;
    ELLLIST functionList;
    ELLLIST variableList;
    ELLLIST bptList;
    ELLLIST filterList;
    ELLLIST guiGroupList;
    void *pathPvt;
    struct dbPvd *ppvd;
    struct gphPvt *pgpHash;
    short ignoreMissingMenus;
    short loadCdefs;
} dbBase;

typedef dbBase DBBASE;

typedef struct dbRecordNode
{
    ELLNODE node;
    void *precord;
    char *recordname;
    ELLLIST infoList; /*LIST head of info nodes*/
    int flags;
    struct dbRecordNode *aliasedRecnode; /* NULL unless flags|DBRN_FLAGS_ISALIAS */
} dbRecordNode;

typedef struct dbInfoNode
{ /*non-field per-record information*/
    ELLNODE node;
    char *name;
    char *string;
    void *pointer;
} dbInfoNode;

typedef struct dbEntry
{
    DBBASE *pdbbase;
    dbRecordType *precordType;
    dbFldDes *pflddes;
    dbRecordNode *precnode;
    dbInfoNode *pinfonode;
    void *pfield;
    char *message;
    short indfield;
} DBENTRY;

typedef void (*dbCaCallback)(void *userPvt);

typedef struct oldChannelNotify *chid;
typedef struct oldSubscription *evid;
#define MAX_UNITS_SIZE 8

typedef struct caLink
{
    ELLNODE node;
    int refcount;
    epicsMutexId lock;
    struct link *plink;
    char *pvname;
    chid chid;
    short link_action;
    /* The following have new values after each data event*/
    epicsEnum16 sevr;
    epicsEnum16 stat;
    epicsTimeStamp timeStamp;
    /* The following have values after connection*/
    short dbrType;
    unsigned long elementSize;  /* size of one element in pgetNative */
    unsigned long nelements;    /* PVs max array size */
    unsigned long usedelements; /* currently used in pgetNative */
    unsigned long putnelements; /* currently used in pputNative */
    char hasReadAccess;
    char hasWriteAccess;
    char isConnected;
    char gotFirstConnection;
    /* The following are for dbCaAddLinkCallback */
    dbCaCallback connect;
    dbCaCallback monitor;
    void *userPvt;
    /* The following are for write request */
    short putType;
    dbCaCallback putCallback;
    void *putUserPvt;
    /* The following are for access to additional attributes*/
    char gotAttributes;
    dbCaCallback getAttributes;
    void *getAttributesPvt;
    /* The following have values after getAttribEventCallback*/
    double controlLimits[2];
    double displayLimits[2];
    double alarmLimits[4];
    short precision;
    char units[MAX_UNITS_SIZE]; /* units of value */
    /* The following are for handling data*/
    void *pgetNative;
    char *pgetString;
    void *pputNative;
    char *pputString;
    evid evidNative;
    evid evidString;
    char gotInNative;
    char gotInString;
    char gotOutNative;
    char gotOutString;
    char newOutNative;
    char newOutString;
    unsigned char scanningOnce;
    /* The following are for dbcar*/
    unsigned long nDisconnect;
    unsigned long nNoWrite; /*only modified by dbCaPutLink*/
    unsigned long nUpdate;
} caLink;
