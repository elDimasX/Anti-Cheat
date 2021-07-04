/*


Todas as funções, importações e váriaveis estão aqui


*/


#include <fltKernel.h>

// Operações que queremos verificar na função ProcessChanged (encontrado abaixo)
#define PROCESS_TERMINATE		(0x0001)
#define PROCESS_VM_READ			(0x0010)
#define PROCESS_VM_WRITE		(0x0020)
#define PROCESS_VM_OPERATION	(0x0008)
#define PROCESS_SUSPEND_RESUME	(0x0800)
#define PROCESS_SET_INFORMATION (0x0200)
#define PROCESS_SET_PORT		(0x0800)
#define PROCESS_SET_SESSIONID	(0x0004)
#define PROCESS_CREATE_PROCESS	(0x0080)

// http://www.codewarrior.cn/ntdoc/wrk/ps/PsReferenceProcessFilePointer.htm
NTSTATUS
PsReferenceProcessFilePointer(
	IN  PEPROCESS Process,
	OUT PVOID* OutFileObject
);

/*

Abaixo, você encontra a definição de todas as funções

*/

// Inicialização do driver
NTSTATUS DriverEntry(_In_ PDRIVER_OBJECT DriverObject, _In_ PUNICODE_STRING RegistryPath);

// Descarregamento do driver
VOID Unload(_In_ PDRIVER_OBJECT DriverObject);

// Adiciona a proteção de processo
NTSTATUS InstallProcessProtector();

// Remove a proteção a de processo
VOID UnInstallProcessProtector();

// Quando um processo é modificado, essa função será chamada
OB_PREOP_CALLBACK_STATUS ProcessChanged(
	_In_ PVOID RegistrationContext,
	_In_ POB_PRE_OPERATION_INFORMATION Information
);

// Verifica se o processo deve ou não ser protegido, além de verificar a porta e outras coisas
BOOLEAN ProcessGranted(_In_ PEPROCESS Process);

// Obtém o local completo apartir de um processo
PUNICODE_STRING GetFullProcessName(
	_In_ PEPROCESS Process
);
