/*


Anti-Cheat com kernel mode

Meu GitHub: https://github.com/elDimasX


*/

#include "header.h"
#include "processprotect.h"

NTSTATUS DriverEntry(_In_ PDRIVER_OBJECT DriverObject, _In_ PUNICODE_STRING RegistryPath)
{
	KdPrint(("O driver de anti-cheat está sendo carregado..."));

	DriverObject->DriverUnload = Unload;
	NTSTATUS Status = STATUS_SUCCESS;

	Status = InstallProcessProtector();

	KdPrint(("Driver carregado com sucesso!"));
	return Status;
}

VOID Unload(_In_ PDRIVER_OBJECT DriverObject)
{
	KdPrint(("O driver de anti-cheat está sendo descarregado..."));
	UnInstallProcessProtector();
	KdPrint(("O driver de anti-cheat foi descarregado"));
}

BOOLEAN ProcessGranted(_In_ PEPROCESS Process)
{
	ANSI_STRING ProcessName;
	BOOLEAN Granted = FALSE;

	__try {

		NTSTATUS Status = RtlUnicodeStringToAnsiString(
			&ProcessName,
			(UNICODE_STRING*)GetFullProcessName(Process),
			TRUE
		);

		if (!NT_SUCCESS(Status))
		{
			KdPrint(("Falhou ao converter UNICODE para ANSI, erro: %x", Status));
			return Granted;
		}

		// Adicione os processos para serem protegidos aqui
		if (strstr(_strupr(ProcessName.Buffer), "C:\\A.EXE"))
		{
			Granted = TRUE;
			KdPrint(("Protegendo o processo contra modificações: %s", ProcessName.Buffer));
		}

		RtlFreeAnsiString(&ProcessName);

	} __except(EXCEPTION_EXECUTE_HANDLER){}

	return Granted;
}

PUNICODE_STRING GetFullProcessName(
	_In_ PEPROCESS Process
)
{
	__try {

		PFILE_OBJECT FileObject;
		POBJECT_NAME_INFORMATION FileObjectInfo;

		NTSTATUS Status = PsReferenceProcessFilePointer(Process, &FileObject);

		if (!NT_SUCCESS(Status))
		{
			KdPrint(("Falhou ao obter o ponteiro do arquivo apartir do processo, erro: %x", Status));
			return NULL;
		}

		Status = IoQueryFileDosDeviceName(FileObject, &FileObjectInfo);

		if (!NT_SUCCESS(Status))
		{
			KdPrint(("Falou ao obter o nome do arquivo, erro: %x", Status));
			return NULL;
		}

		// Retorne o nome do arquivo em UNICODE_STRING
		return &(FileObjectInfo->Name);

	} __except (EXCEPTION_EXECUTE_HANDLER)
	{ }

	return NULL;
}


