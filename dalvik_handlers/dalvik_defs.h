////////////////////////////////////////////////////////////////////////////////////
//
//      FILE:           dalvik_defs.h
//
//      DESCRIPTION:	imported Dalvik VM definitions
//
//      SEE ALSO:
//      AUTHOR:         L.Astakhov
//      COMPANY NAME:   Samsung Research Center in Moscow
//      DEPT NAME:      Advanced Software Group
//      CREATED:        2011.07.08
//      VERSION:        1.0
//      REVISION DATE:  2011.07.08
//
////////////////////////////////////////////////////////////////////////////////////

#ifndef __DALVIK_DEFS_H
#define __DALVIK_DEFS_H

typedef unsigned short int __uint16_t;
typedef unsigned int __uint32_t;

typedef union Lock {
    __uint32_t  thin;
    void*	    mon;
} Lock;

struct ClassObject;

typedef struct Object {
    struct ClassObject*    clazz;
    Lock            lock;
} Object;

typedef enum ClassStatus {
    CLASS_ERROR         = -1,

    CLASS_NOTREADY      = 0,
    CLASS_LOADED        = 1,
    CLASS_PREPARED      = 2,    /* part of linking */
    CLASS_RESOLVED      = 3,    /* part of linking */
    CLASS_VERIFYING     = 4,    /* in the process of being verified */
    CLASS_VERIFIED      = 5,    /* logically part of linking; done pre-init */
    CLASS_INITIALIZING  = 6,    /* class init in progress */
    CLASS_INITIALIZED   = 7,    /* ready to go */
} ClassStatus;

typedef enum PrimitiveType {
    PRIM_NOT        = -1,       /* value is not a primitive type */
    PRIM_BOOLEAN    = 0,
    PRIM_CHAR       = 1,
    PRIM_FLOAT      = 2,
    PRIM_DOUBLE     = 3,
    PRIM_BYTE       = 4,
    PRIM_SHORT      = 5,
    PRIM_INT        = 6,
    PRIM_LONG       = 7,
    PRIM_VOID       = 8,

    PRIM_MAX
} PrimitiveType;
#define PRIM_TYPE_TO_LETTER "ZCFDBSIJV"     /* must match order in enum */

typedef struct InitiatingLoaderList {
    /* a list of initiating loader Objects; grown and initialized on demand */
    Object**  initiatingLoaders;
    /* count of loaders in the above list */
    int       initiatingLoaderCount;
}InitiatingLoaderList;

typedef struct InterfaceEntry {
    /* pointer to interface class */
    struct ClassObject*    clazz;
    /*
     * Index into array of vtable offsets.  This points into the ifviPool,
     * which holds the vtables for all interfaces declared by this class.
     */
    int*            methodIndexArray;
} InterfaceEntry;


typedef union JValue {
	unsigned char		z;
    signed char			b;
    unsigned short		c;
    signed short		s;
    signed int			i;
    signed long long	j;
    float				f;
    double				d;
    void*				l;
} JValue;

typedef struct DexProto {
    const void* dexFile;     /* file the idx refers to */
    __uint32_t protoIdx;                /* index into proto_ids table of dexFile */
} DexProto;


typedef struct Method {
    /* the class we are a part of */
    struct ClassObject*    clazz;

    /* access flags; low 16 bits are defined by spec (could be u2?) */
    __uint32_t      accessFlags;

    /*
     * For concrete virtual methods, this is the offset of the method
     * in "vtable".
     *
     * For abstract methods in an interface class, this is the offset
     * of the method in "iftable[n]->methodIndexArray".
     */
    __uint16_t      methodIndex;

    /*
     * Method bounds; not needed for an abstract method.
     *
     * For a native method, we compute the size of the argument list, and
     * set "insSize" and "registerSize" equal to it.
     */
    __uint16_t      registersSize;  /* ins + locals */
    __uint16_t      outsSize;
    __uint16_t      insSize;

    /* method name, e.g. "<init>" or "eatLunch" */
    const char*     name;

    /*
     * Method prototype descriptor string (return and argument types).
     *
     * TODO: This currently must specify the DexFile as well as the proto_ids
     * index, because generated Proxy classes don't have a DexFile.  We can
     * remove the DexFile* and reduce the size of this struct if we generate
     * a DEX for proxies.
     */
    DexProto        prototype;

    /* short-form method descriptor string */
    const char*     shorty;

    /*
     * The remaining items are not used for abstract or native methods.
     * (JNI is currently hijacking "insns" as a function pointer, set
     * after the first call.  For internal-native this stays null.)
     */

    /* the actual code */
    const __uint16_t*  insns;          /* instructions, in memory-mapped .dex */

    /* cached JNI argument and return-type hints */
    int             jniArgInfo;

}Method;


typedef struct ClassObject {
    Object          obj;                /* MUST be first item */

    /* leave space for instance data; we could access fields directly if we
       freeze the definition of java/lang/Class */
    __uint32_t      instanceData[4];

    /* UTF-8 descriptor for the class; from constant pool, or on heap
       if generated ("[C") */
    const char*     descriptor;
    char*           descriptorAlloc;

    /* access flags; low 16 bits are defined by VM spec */
    __uint32_t      accessFlags;

    /* VM-unique class serial number, nonzero, set very early */
    __uint32_t      serialNumber;

    /* DexFile from which we came; needed to resolve constant pool entries */
    /* (will be NULL for VM-generated, e.g. arrays and primitive classes) */
    void*	         pDvmDex;

    /* state of class initialization */
    ClassStatus     status;

    /* if class verify fails, we must return same error on subsequent tries */
    struct ClassObject*    verifyErrorClass;

    /* threadId, used to check for recursive <clinit> invocation */
    __uint32_t      initThreadId;

    /*
     * Total object size; used when allocating storage on gc heap.  (For
     * interfaces and abstract classes this will be zero.)
     */
    size_t          objectSize;

    /* arrays only: class object for base element, for instanceof/checkcast
       (for String[][][], this will be String) */
    struct ClassObject*    elementClass;

    /* class object representing an array of this class; set on first use */
    struct ClassObject*    arrayClass;

    /* arrays only: number of dimensions, e.g. int[][] is 2 */
    int             arrayDim;

    /* primitive type index, or PRIM_NOT (-1); set for generated prim classes */
    PrimitiveType   primitiveType;

    /* superclass, or NULL if this is java.lang.Object */
    struct ClassObject*    super;

    /* defining class loader, or NULL for the "bootstrap" system loader */
    Object*         classLoader;

    /* initiating class loader list */
    /* NOTE: for classes with low serialNumber, these are unused, and the
       values are kept in a table in gDvm. */
    InitiatingLoaderList initiatingLoaderList;

    /* array of interfaces this class implements directly */
    int             interfaceCount;
    struct ClassObject**   interfaces;

    /* static, private, and <init> methods */
    int             directMethodCount;
    Method*         directMethods;

    /* virtual methods defined in this class; invoked through vtable */
    int             virtualMethodCount;
    Method*         virtualMethods;

    /*
     * Virtual method table (vtable), for use by "invoke-virtual".  The
     * vtable from the superclass is copied in, and virtual methods from
     * our class either replace those from the super or are appended.
     */
    int             vtableCount;
    Method**        vtable;

    /*
     * Interface table (iftable), one entry per interface supported by
     * this class.  That means one entry for each interface we support
     * directly, indirectly via superclass, or indirectly via
     * superinterface.  This will be null if neither we nor our superclass
     * implement any interfaces.
     *
     * Why we need this: given "class Foo implements Face", declare
     * "Face faceObj = new Foo()".  Invoke faceObj.blah(), where "blah" is
     * part of the Face interface.  We can't easily use a single vtable.
     *
     * For every interface a concrete class implements, we create a list of
     * virtualMethod indices for the methods in the interface.
     */
    int             iftableCount;
    InterfaceEntry* iftable;

    /*
     * The interface vtable indices for iftable get stored here.  By placing
     * them all in a single pool for each class that implements interfaces,
     * we decrease the number of allocations.
     */
    int             ifviPoolCount;
    int*            ifviPool;

    /* static fields */
    int             sfieldCount;
    void*		    sfields;

    /* instance fields
     *
     * These describe the layout of the contents of a DataObject-compatible
     * Object.  Note that only the fields directly defined by this class
     * are listed in ifields;  fields defined by a superclass are listed
     * in the superclass's ClassObject.ifields.
     *
     * All instance fields that refer to objects are guaranteed to be
     * at the beginning of the field list.  ifieldRefCount specifies
     * the number of reference fields.
     */
    int             ifieldCount;
    int             ifieldRefCount; // number of fields that are object refs
    void*		    ifields;

    /* bitmap of offsets of ifields */
    __uint32_t		refOffsets;

    /* source file name, if known */
    const char*     sourceFile;
}ClassObject;

typedef struct Thread
{

}Thread;

enum {
    ACC_PUBLIC       = 0x00000001,       // class, field, method, ic
    ACC_PRIVATE      = 0x00000002,       // field, method, ic
    ACC_PROTECTED    = 0x00000004,       // field, method, ic
    ACC_STATIC       = 0x00000008,       // field, method, ic
    ACC_FINAL        = 0x00000010,       // class, field, method, ic
    ACC_SYNCHRONIZED = 0x00000020,       // method (only allowed on natives)
    ACC_SUPER        = 0x00000020,       // class (not used in Dalvik)
    ACC_VOLATILE     = 0x00000040,       // field
    ACC_BRIDGE       = 0x00000040,       // method (1.5)
    ACC_TRANSIENT    = 0x00000080,       // field
    ACC_VARARGS      = 0x00000080,       // method (1.5)
    ACC_NATIVE       = 0x00000100,       // method
    ACC_INTERFACE    = 0x00000200,       // class, ic
    ACC_ABSTRACT     = 0x00000400,       // class, method, ic
    ACC_STRICT       = 0x00000800,       // method
    ACC_SYNTHETIC    = 0x00001000,       // field, method, ic
    ACC_ANNOTATION   = 0x00002000,       // class, ic (1.5)
    ACC_ENUM         = 0x00004000,       // class, field, ic (1.5)
    ACC_CONSTRUCTOR  = 0x00010000,       // method (Dalvik only)
    ACC_DECLARED_SYNCHRONIZED =
                       0x00020000,       // method (Dalvik only)
    ACC_CLASS_MASK =
        (ACC_PUBLIC | ACC_FINAL | ACC_INTERFACE | ACC_ABSTRACT
                | ACC_SYNTHETIC | ACC_ANNOTATION | ACC_ENUM),
    ACC_INNER_CLASS_MASK =
        (ACC_CLASS_MASK | ACC_PRIVATE | ACC_PROTECTED | ACC_STATIC),
    ACC_FIELD_MASK =
        (ACC_PUBLIC | ACC_PRIVATE | ACC_PROTECTED | ACC_STATIC | ACC_FINAL
                | ACC_VOLATILE | ACC_TRANSIENT | ACC_SYNTHETIC | ACC_ENUM),
    ACC_METHOD_MASK =
        (ACC_PUBLIC | ACC_PRIVATE | ACC_PROTECTED | ACC_STATIC | ACC_FINAL
                | ACC_SYNCHRONIZED | ACC_BRIDGE | ACC_VARARGS | ACC_NATIVE
                | ACC_ABSTRACT | ACC_STRICT | ACC_SYNTHETIC | ACC_CONSTRUCTOR
                | ACC_DECLARED_SYNCHRONIZED),
};

inline int IsNativeMethod(const Method* method) {
    return (method->accessFlags & ACC_NATIVE) != 0;
}

typedef struct InterpState
{

}InterpState;

typedef InterpState MterpGlue;


#endif
