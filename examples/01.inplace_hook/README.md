# Deviate - Inplace Example

This example demonstrates how **deviate** can be used within the source code  
of a binary in order to detour a function away from it's original behaviour.


#### Intended Usage
1. Compile the target
2. Run the target and observe it's runtime behaviour
3. Expected output  
   ```bash
   Legend: [-] Normal function call | [+] Detoured function call | [!] Deviate library action

   [-] foo(5) = 5
   [!] foo lambda detoured
   [+] lambda detour foo(5) = 25
   [!] foo(5) patched to original function
   [-] foo(5) = 5
   [!] interceptor object created with lambda
   [+] interceptor foo(5) = 'All your base are belong to us'
   [!] foo(5) restored
   [-] foo(5) = 5
   [!] interceptor context created
   [+] trampoline hooked foo; foo(5) = 10; Returning to foo:
   [-] foo(5) = 5
   [!] interceptor context destroyed
   [!] interceptor context created
   [+] function hooked; bar(5) = 'whatever your heart desires'; Returning to foo with 3x
   [-] foo(15) = 15
   [!] interceptor context destroyed
   [-] foo(5) = 5
   ```
