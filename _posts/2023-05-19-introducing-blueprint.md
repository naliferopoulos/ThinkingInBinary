---
title: "Introducing Blueprint"
categories:
  - Blog
tags:
  - Red Teaming
  - Metaprogramming
  - Templating
  - Tool
---

As discussed in our previous post, regarding [Fairplay](../fairplay/fairplay-blog.md), during Red Team engagements a lot of focus is shifted into preserving and protecting the malware. Fairplay does its fair share of work to provide us with the information on when we get detected, but before that, we needed a way to make sure that each and every single payload that we utilize is unique. This ultimately prevents mass-actions taken against static information in our payloads, since each payload is always unique statically and perhaps even sometimes behaviorally. 

However, not all payloads are the same. Red Teams usually assess and evaluate multiple potential entrypoints, each one with its own caveats. There are vast differences between platforms, technological stacks and contexts. There are for example native Windows executables, managed .NET assemblies, VBScript/JScript HTA or CHM enabled documents, etc. The plethora of possible combinations of attack chains and scenarios is huge when the potential options are served with a multitude of different attack chains, comprised of sets of TTPs. The previous example now becomes:

- Native Windows Service Executable that performs self injection of shellcode using RtlRunOnceExecuteOnce
- .NET executable that performs AppDomainManager hijack to remote process shellcode injection targetting Explorer.exe
- ...

As one can observe, the list quickly grows out of hand rather quickly. This created a nuance from both the developers' as well as the operators' perspectives. It became apparent that producing unique builds that are comprised of smaller, TTP based modules, in multiple "wrapper" formats (.exe, .dll, .hta, etc.) at will without deep diving in the code required for an across the board solution that could template malware at source code level. 

### Introducing Blueprint

Blueprint is a `python3` source-code level modular templating solution based on [Jinja](https://jinja.palletsprojects.com/en/3.1.x/). It is developed by the Hackcraft Red Team and is open-source and freely available [here](https://github.com/Hackcraft-Labs/Blueprint).

### Jinja boilerplate

Blueprint extends the classic Jinja syntax and offers modularity through the use of `filters`. Filters, functionality native to Jinja, are essentially python-backed functions that receive input which they operate on and return the output. They can be called in the Jinja context in the form of pipelines, which are evaluated to the final outputs. An example is as follows:

```jinja
{{ "Example" | filter1 | filter2 }}
```

Here, the expression inside the double braces will be evaluated as the equivalent of the following python snippet:

```python
filter2(filter1("Example"))
```

Example definitions of `filter1` and `filter2` could be as follows:

```python
def filter1(inp):
    return inp + "1"

def filter2(inp):
    return inp + "2"
```

As a result the above expression would be evaluated to `Example12`.

### Blueprint modules

Blueprint offers an extensive list of sinister modules which we use extensively in our malware, which of course can be extended in `python3` and is as follows:

- Input/Output
  - `Content` : Retrieves the binary contents of a file
  - `Output` : Writes to a binary file
- Crypto
  - `AES` : Performs AES encryption with a randomly generated key and IV
  - `XOR` : Performs XOR encryption with a randomly generated single-byte key
- Hashing
  - `DJB2` : Computes the DJB2 hash of the input, which is useful when hashing known strings for obfuscation
- Format
  - `HexArr` : Formats the input to a comma-separated array of hex represented bytes 
  - `DecArr` : Formats the input to a comma-separated array of decimal represented bytes 

The author of the template can use these modules as a language-agnostic build-time metaprogramming environment to tweak certain aspects of the code. Consider for example the following use case:

```c
// File: example.h.tpl

// In this malware, we need to execute a piece of shellcode.
// The shellcode is AES encrypted at rest and decrypted before being self-injected at runtime.

// Let us define a C array of bytes to hold the AES encryption key.
// Notice the Blueprint templating which will evaluate to the value of the variable AES_KEY as a hex-array.
unsigned char key[] = { {{ AES_KEY | hexarr }}} ;

// Same process, but for the encryption IV this time.
unsigned char iv[] = { {{ AES_IV | hexarr } }}

// Now for the actual shellcode, let us:
// - Retrieve the contents of payload.bin 
// - Encrypt it with the aes module (Random key and IV will be generated and output to AES_KEY and AES_IV respectively)
// - Represent it as a hex-array
unsigned char payload = { {{ "payload.bin" | content | aes | hexarr }} }
```

Notice how this is not constrained to a certain compiler, let alone a specific language or context. This can be used in any source code file and can of course be extended at will.

### Behavioral modularity

In Blueprint templates, we can also leverage Jinja control-flow primitives to offer a way to the operator to toggle certain features on or off at build time, without having to make changes to the code. Consider the following example:

```c
// File: example.c.tpl

// Include our payload header file, produced by example.h.tpl
#include "example.h"

// ... snip ...
int __stdcall WinMain(HINSTANCE hInst, HINSTANCE hInstPrev, PSTR cmdline, int cmdshow)
{
    // Decrypt the shellcode
    perform_aes_decryption(payload, sizeof(payload), key, iv);

    // If PATCH_ETW is set, then disable it.
    {% if PATCH_ETW %}
        disable_etw();
    {% endif %}

    // Perform the injection.
    inject(payload, sizeof(payload));
}
```

### Metaprogramming concepts

Another cool side-effect of templating is that you can provide an abstract interface to the operations team. Consider for example the use case where malware can target a list of processes to inject shellcode to, which can vary in size. Also, all these strings should be encrypted in some way to prevent static identification. This becomes as simple as:

```c
{% for process_name in INJECT_TO_PROCESSES %}
unsigned char proc_{{ loop.index }}_str[] = { {{ process_name | xor | hexarr }} };
{% endfor %}
```

We just defined a number of C arrays containing the XOR encrypted versions of the process name strings defined in the python array `INJECT_TO_PROCESSES`.

### Bringing it all together

Now all that's left is wrapping up this hot mess of features into a neat little present before presenting the dev team's work to the operators, which is offered through the magic of `JSON configuration files`. An example for our case would be as follows:

```json
{
    "filters":[
        "crypto.AES",
        "crypto.XOR",
        "io.Content"
    ],
    "targets":[
        {
            "input":"example.h.tpl",
            "output":"example.h",
            "variables":{}
        },
        {
            "input":"example.c.tpl",
            "output":"example.c",
            "variables":{
                "INJECT_TO_PROCESSES":["explorer.exe", "TextInputHost.exe"],
                "PATCH_ETW":true
            }
        }
    ]
}
```

This configuration file can be editted at will by the operations team to provide malleable capabilities to each campaign and scenario, while allowing for it to morph on its own as well during each built, to provide OPSEC against static checks. It is parsed by Blueprint, in the following way:

- The `filters` defined are imported into the context.
- For each entry in `targets`: 
  - The `input` file is evaluated as a Blueprint template.
  - The `variables` are inserted into the context.
  - The end result is written to the file defined in the `output`.

Then, your usual build pipeline continues, targetting the files output by Blueprint. Again, this supports anything from an VS/MSBuild C/C++ project to a JScript CHM Help Studio project. 

That's it, we are done! *Almost*...

### A love letter to the devs

Blueprint abstracts away many of the nitty gritty details of the underlying malware code, but after using it for a while it was pretty aparrent that it completely broke syntax highlighting on every editor out there. Unfortunatelly, the solution to this can not be easily abstracted away, but we have created a small plugin for Visual Studio Code to facilitate authoring Blueprint malware templates, which supports syntax highlighting for Blueprint templates containing the following languages/contexts:
- C/C++
- C#
- Batch

The list can of course be further extended. May the eye-strain be reduced! :)

### Contributions

Contributions to the code base of Blueprint are very much welcome through Pull Requests submitted on its repository, both for the framework as well as for new modules that provide functionality related to malware development.

### Note
This article was originally uploaded at the [Hackcraft Blog](https://www.hackcraft.gr/2023/05/blueprint-blog/).