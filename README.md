# IndirectSyscalls

Tired of getting flagged in every stack trace known to AV-kind because your "next-gen" syscall invoker runs through unbacked RWX memory?  
Tired of being one YARA scan away from dumped memory and a ruined day?

I've got a solution!

Both those detection vectors are super simple, ones literally "is this in ntdll.dll?", the other's "is there syscall instruction OUTSIDE of ntdll.dll", see a pattern?
Yes ntdll.dll is special. (And the two other DLL's no one, including me talks about), because it provides the transaction layer between usermode and super-scary kernel.
Syscalls are meant to exist only within ntdll.dll, if they exist outside its a hugee red flag for any protection software.

Now if you're an actual developer here to learn something I'd reccomend going and reading the source, if you're not in the mood for reading rust here goes;
1. Parse PEB->LdrLoadedModules->"ntdll.dll"
2. Parse headers->exports
3. Verify syscall ABI
5. Put into global table
6. Make public API func copying syscall firing ABI
7. Make that use the global table to execute the relevant syscall
8. Call your favorite syscall with your API

> "But Damon hooks! Isn't that the whole reason we avoid ntdll.dll anyway?"

Yes.. but this *only* executes the *syscall prologue*, I skip any surrounding silly jmps/calls
Now that raises problems when they're forwaded hooks and now I have a headache.
Enjoy the PoC.
