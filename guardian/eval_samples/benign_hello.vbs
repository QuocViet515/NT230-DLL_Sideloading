Set fso = CreateObject("Scripting.FileSystemObject")
Set temp = fso.GetSpecialFolder(2)
Set f = fso.CreateTextFile(temp & "\guardian_eval_note.txt", True)
f.WriteLine "guardian eval benign vbs"
f.Close

