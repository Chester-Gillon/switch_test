function compile_for_windows
% Build npcap programs for Windows using the MinGW compiler installed with
% MATLAB.
%
% Compile using MinGW since NPCAP requires Visual Studio 2015 or later to
% get C99 support.
%
% NPCAP installs the DLLs in the c:\Windows\System32\Npcap directory which
% is not by default on the path. The executables created won't start unless
% that directory is on the path.
%
% The NPCAP examples are built using the Visual Studio "Delay Load" option
% for wpcap.dll, and contain a LoadNpcapDlls() function which sets the DLL
% load directory at runtime. MinGW doesn't have the equivalent of the
% "Delay Load" option in the compiler, and therefore the source code
% doesn't have the equivalent of the LoadNpcapDlls() function.

% Locate the mingw compiler installed with Matlab
compiler_info = mex.getCompilerConfigurations;
mingw_index = find(strcmp({compiler_info.ShortName},'mingw64'));
if isempty(mingw_index)
    fprintf ('Unable to locate mingw compiler\n');
    return
end
mingw_path=fullfile(compiler_info(mingw_index).Location,'bin');
gcc_exe = fullfile (mingw_path, 'gcc');

% Directories to find the NPCAP SDK files to build against.
npcap_root = 'C:\npcap-sdk-1.10';
npcap_include_dir = fullfile (npcap_root, 'Include');
npcap_lib_dir = fullfile (npcap_root, 'Lib', 'x64');

% MinGW options to build against NPCAP
npcap_options = ['-I ' npcap_include_dir ' -L ' npcap_lib_dir ' -l wpcap -l Ws2_32'];

% Root directory for the build of the programs is the directory containing
% this function
[build_root,~,~] = fileparts (mfilename('fullpath'));
exe_dir = fullfile (build_root, 'Debug');

if ~isfolder (exe_dir)
    mkdir (exe_dir);
end

% Compile the program.
% The PATH is set to the MinGW directory as gcc needs to load some DLLs in
% the same directory.
system(['set PATH=' mingw_path ';%PATH && ' ...
    gcc_exe ' -Wall -mno-ms-bitfields ' fullfile(build_root, 'switch_test_main.c') ...
    ' -o '  fullfile(exe_dir,'switch_test.exe') ...
    ' ' npcap_options]);

end
