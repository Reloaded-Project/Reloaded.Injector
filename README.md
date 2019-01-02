

<div align="center">
	<h1>Project Reloaded: Injector </h1>
	<img src="https://i.imgur.com/BjPn7rU.png" width="150" align="center" />
	<br/> <br/>
	<strong><i>Crossing the WoW boundaries</i></strong>
	<br/> <br/>
	<!-- Coverage -->
	<a href="https://codecov.io/gh/Reloaded-Project/Reloaded.Injector">
		<img src="https://codecov.io/gh/Reloaded-Project/Reloaded.Injector/branch/master/graph/badge.svg" alt="Coverage" />
	</a>
	<!-- NuGet -->
	<a href="https://www.nuget.org/packages/Reloaded.Injector">
		<img src="https://img.shields.io/nuget/v/Reloaded.Injector.svg" alt="NuGet" />
	</a>
	<!-- Build Status -->
	<a href="https://ci.appveyor.com/project/sewer56lol/reloaded-injector">
		<img src="https://ci.appveyor.com/api/projects/status/xtq8rtwqh4cw5jg2?svg=true" alt="Build Status" />
	</a>
</div>

# Introduction
Reloaded.Injector is a DLL Injector, what is there more to say?

Well, there are many kinds of DLL Injectors and libraries out there in the wild, so I guess the question is rather *why did I write another one and use something already out there*?

![XKCD: Standards](https://imgs.xkcd.com/comics/standards.png)
 

Well, there indeed are many DLL injectors, but for C# one unfortunately did not exist that had the particular feature set I needed: Inject DLLs into *both x86 and x64 targets* from the same program.

That's the reason this project exists.

## Notable Features
- Find & Call exported methods in injected/loaded remote DLLs.
- Execute LoadLibraryW, GetProcAddress in remote processes.
- Does not load DLLs into current process. Safe for DLLs with code in DllMain.
- Does not waste/leave memory in remote process after injection.
- Uses circular buffer for parameter passing. No slow heap allocations in remote process for calling functions.
-  **All of this is also supported for x86 processes from x64 processes.**.

## Getting Started

To get started, install the package from NuGet and simply create a new instance of the `Injector` class from the `Reloaded.Injector` namespace:

```csharp
injector = new Injector(process);
``` 
You're done; that's all you need to do.

PS. When you're done, be a good person and dispose your waste 😉.

```csharp
injector.Dispose();
```

## Contributions
As with the standard for all of the `Reloaded-Project`, repositories; contributions are very welcome and encouraged.

Feel free to implement new features, make bug fixes or suggestions so long as they are accompanied by an issue with a clear description of the pull request 😉.

