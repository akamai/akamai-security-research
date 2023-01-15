#include <windows.h>

// RPC Protocol Sequence:
#define ncacn_ip_tcp 1
#define ncacn_np 2
#define ncalrpc 3
#define ncacn_http	4

// RPC Authentication Level:
#define RPC_C_AUTHN_LEVEL_DEFAULT       0
#define RPC_C_AUTHN_LEVEL_NONE          1
#define RPC_C_AUTHN_LEVEL_CONNECT       2
#define RPC_C_AUTHN_LEVEL_CALL          3
#define RPC_C_AUTHN_LEVEL_PKT           4
#define RPC_C_AUTHN_LEVEL_PKT_INTEGRITY 5
#define RPC_C_AUTHN_LEVEL_PKT_PRIVACY   6

// RPC Authentication Service:
#define RPC_C_AUTHN_NONE 0
#define RPC_C_AUTHN_DCE_PRIVATE 1
#define RPC_C_AUTHN_DCE_PUBLIC 2
#define RPC_C_AUTHN_DEC_PUBLIC 4
#define RPC_C_AUTHN_GSS_NEGOTIATE 9
#define RPC_C_AUTHN_WINNT 10
#define RPC_C_AUTHN_GSS_SCHANNEL 14
#define RPC_C_AUTHN_GSS_KERBEROS 16
#define RPC_C_AUTHN_DPA 17
#define RPC_C_AUTHN_MSN 18
#define RPC_C_AUTHN_KERNEL 20
#define RPC_C_AUTHN_DIGEST 21
#define RPC_C_AUTHN_NEGO_EXTENDER 30
#define RPC_C_AUTHN_PKU2U 31
#define RPC_C_AUTHN_LIVE_SSP 32
#define RPC_C_AUTHN_LIVEXP_SSP 35
#define RPC_C_AUTHN_CLOUD_AP 36
#define RPC_C_NETLOGON 68 
#define RPC_C_AUTHN_MSONLINE 82 
#define RPC_C_AUTHN_MQ 100
#define RPC_C_AUTHN_DEFAULT 0xffffffff

//
// RPC_CALL_ATTRIBUTS structs were taken from https://github.com/tpn/winsdk-10/blob/master/Include/10.0.16299.0/shared/rpcasync.h
//

// RPC_CALL_ATTRIBUTES_V1:

typedef struct tagRPC_CALL_ATTRIBUTES_V1_W
{
    unsigned int Version;                               
    unsigned long Flags;                                
    unsigned long ServerPrincipalNameBufferLength;      
    unsigned short *ServerPrincipalName;                
    unsigned long ClientPrincipalNameBufferLength;      
    unsigned short *ClientPrincipalName;                
    unsigned long AuthenticationLevel;                  
    unsigned long AuthenticationService;                
    BOOL NullSession;									
} RPC_CALL_ATTRIBUTES_V1_W;

typedef struct tagRPC_CALL_ATTRIBUTES_V1_A
{
    unsigned int Version;                               
    unsigned long Flags;                                
    unsigned long ServerPrincipalNameBufferLength;      
    unsigned char *ServerPrincipalName;                
    unsigned long ClientPrincipalNameBufferLength;     
    unsigned char *ClientPrincipalName;                
    unsigned long AuthenticationLevel;                 
    unsigned long AuthenticationService;               
    BOOL NullSession;								
} RPC_CALL_ATTRIBUTES_V1_A;


// RPC_CALL_ATTRIBUTES_V2:

typedef struct tagRPC_CALL_ATTRIBUTES_V2_W
{
    unsigned int Version;                               
    unsigned long Flags;                                
    unsigned long ServerPrincipalNameBufferLength;      
    unsigned short *ServerPrincipalName;                
    unsigned long ClientPrincipalNameBufferLength;      
    unsigned short *ClientPrincipalName;                
    unsigned long AuthenticationLevel;                  
    unsigned long AuthenticationService;                
    BOOL NullSession;									
    BOOL KernelModeCaller;                              
    unsigned long ProtocolSequence;                     
    RpcCallClientLocality IsClientLocal;                
    HANDLE ClientPID; 									
    unsigned long CallStatus;                           
    RpcCallType CallType;                     		    
    RPC_CALL_LOCAL_ADDRESS_V1 *CallLocalAddress;        
    unsigned short OpNum;                     		    
    UUID InterfaceUuid;                       		    
} RPC_CALL_ATTRIBUTES_V2_W;
    
typedef struct tagRPC_CALL_ATTRIBUTES_V2_A
{
    unsigned int Version;                               
    unsigned long Flags;                                
    unsigned long ServerPrincipalNameBufferLength;      
    unsigned char *ServerPrincipalName;                 
    unsigned long ClientPrincipalNameBufferLength;      
    unsigned char *ClientPrincipalName;                 
    unsigned long AuthenticationLevel;                  
    unsigned long AuthenticationService;                
    BOOL NullSession;									
    BOOL KernelModeCaller;								
    unsigned long ProtocolSequence;						
    unsigned long IsClientLocal;
    HANDLE ClientPID; 
    unsigned long CallStatus;
    RpcCallType CallType;
    RPC_CALL_LOCAL_ADDRESS_V1 *CallLocalAddress;	
    unsigned short OpNum;
    UUID InterfaceUuid;    
} RPC_CALL_ATTRIBUTES_V2_A;


// RPC_CALL_ATTRIBUTES_V3:

typedef struct tagRPC_CALL_ATTRIBUTES_V3_W
{
    unsigned int Version;
    unsigned long Flags;
    unsigned long ServerPrincipalNameBufferLength;
    unsigned short *ServerPrincipalName;
    unsigned long ClientPrincipalNameBufferLength;
    unsigned short *ClientPrincipalName;
    unsigned long AuthenticationLevel;
    unsigned long AuthenticationService;
    BOOL NullSession;
    BOOL KernelModeCaller;
    unsigned long ProtocolSequence;
    RpcCallClientLocality IsClientLocal;
    HANDLE ClientPID; 
    unsigned long CallStatus;
    RpcCallType CallType;
    RPC_CALL_LOCAL_ADDRESS_V1 *CallLocalAddress;	
    unsigned short OpNum;
    UUID InterfaceUuid;
    unsigned long          ClientIdentifierBufferLength;
    unsigned char          *ClientIdentifier;
} RPC_CALL_ATTRIBUTES_V3_W;
    
typedef struct tagRPC_CALL_ATTRIBUTES_V3_A
{
    unsigned int Version;
    unsigned long Flags;
    unsigned long ServerPrincipalNameBufferLength;
    unsigned char *ServerPrincipalName;
    unsigned long ClientPrincipalNameBufferLength;
    unsigned char *ClientPrincipalName;
    unsigned long AuthenticationLevel;
    unsigned long AuthenticationService;
    BOOL NullSession;
    BOOL KernelModeCaller;
    unsigned long ProtocolSequence;
    unsigned long IsClientLocal;
    HANDLE ClientPID; 
    unsigned long CallStatus;
    RpcCallType CallType;
    RPC_CALL_LOCAL_ADDRESS_V1 *CallLocalAddress;	
    unsigned short OpNum;
    UUID InterfaceUuid;    
    unsigned long          ClientIdentifierBufferLength;
    unsigned char          *ClientIdentifier;
} RPC_CALL_ATTRIBUTES_V3_A;
