/*

Faz as operações para proteger os processos


*/

PVOID RegistrationHandle = NULL;
HANDLE	ProcessType = NULL;

OB_PREOP_CALLBACK_STATUS ProcessChanged(
	_In_ PVOID RegistrationContext,
	_In_ POB_PRE_OPERATION_INFORMATION Information
)
{
	LPSTR ProcssName;
	PACCESS_MASK returnAccess = NULL;
	ACCESS_MASK OriginalAccess = 0;
	HANDLE ProcessPidForThread;

	if (Information->ObjectType == *PsProcessType)
	{
		if (Information->Object == PsGetCurrentProcess())
		{
			return OB_PREOP_SUCCESS;
		}
	}

	else if (Information->ObjectType == *PsThreadType)
	{
		ProcessPidForThread = PsGetThreadProcessId(
			(PETHREAD)Information->Object
		);

		if (ProcessPidForThread == PsGetCurrentProcessId())
		{
			return OB_PREOP_SUCCESS;
		}
	}

	else
	{
		return OB_PREOP_SUCCESS;
	}

	// Se for uma operação feita pelo kernel
	if (Information->KernelHandle == 1)
	{
		return OB_PREOP_SUCCESS;
	}

	if (ProcessGranted((PEPROCESS)Information->Object) == TRUE)
	{
		returnAccess = &Information->Parameters->CreateHandleInformation.DesiredAccess;
		OriginalAccess = Information->Parameters->CreateHandleInformation.OriginalDesiredAccess;
		
		// Só continue se o processo não estiver sendo aberto
		if ((OriginalAccess & PROCESS_CREATE_PROCESS) != PROCESS_CREATE_PROCESS)
		{
			if (
				(OriginalAccess & PROCESS_VM_READ) == PROCESS_VM_READ ||
				(OriginalAccess & PROCESS_VM_WRITE) == PROCESS_VM_WRITE ||
				(OriginalAccess & PROCESS_SET_INFORMATION) == PROCESS_SET_INFORMATION ||
				(OriginalAccess & PROCESS_VM_OPERATION) == PROCESS_VM_OPERATION
				)
			{
				*returnAccess &= STATUS_ABANDONED;
			}
		}
	}

	return OB_PREOP_SUCCESS;
}

VOID AfterKill(
	PVOID RegistrationContext, // Contexto

	// Informações
	POB_POST_OPERATION_INFORMATION Information
)
{
}

NTSTATUS InstallProcessProtector()
{

	OB_CALLBACK_REGISTRATION CallBackRegistry;
	OB_OPERATION_REGISTRATION CallBackOperation;

	CallBackOperation.ObjectType = PsProcessType;
	CallBackOperation.Operations = OB_OPERATION_HANDLE_CREATE;
	CallBackOperation.PostOperation = AfterKill;
	CallBackOperation.PreOperation = ProcessChanged;

	RtlInitUnicodeString(&CallBackRegistry.Altitude, L"370013");

	CallBackRegistry.Version = OB_FLT_REGISTRATION_VERSION;
	CallBackRegistry.OperationRegistrationCount = 1;
	CallBackRegistry.RegistrationContext = NULL;
	CallBackRegistry.OperationRegistration = &CallBackOperation;

	NTSTATUS Status = ObRegisterCallbacks(
		&CallBackRegistry,
		&RegistrationHandle
	);

	if (!NT_SUCCESS(Status))
	{
		return Status;
	}

	return STATUS_SUCCESS;
}

VOID UnInstallProcessProtector()
{
	if (RegistrationHandle)
	{
		ObUnRegisterCallbacks(RegistrationHandle);
	}
}

