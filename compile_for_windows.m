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
npcap_root = '';
npcap_roots = {'C:\npcap-sdk-1.10', 'C:\npcap-sdk-1.15'};
for path_index = 1:length(npcap_roots)
    if isfolder (npcap_roots{path_index})
        npcap_root = npcap_roots{path_index};
    end
end
if isempty(npcap_root)
    fprintf ('Unable to locate NPCAP SDK\n');
    return
end
npcap_include_dir = fullfile (npcap_root, 'Include');
npcap_lib_dir = fullfile (npcap_root, 'Lib', 'x64');

% MinGW options to build against NPCAP
npcap_options = ['-I ' npcap_include_dir ' -L ' npcap_lib_dir ' -l wpcap -l Ws2_32'];

% Build the program for Debug and Release
build_configurations={'Debug', 'Release'};
build_configuration_flags={' -g', ' -O3'};

% Root directory for the build of the programs is the directory containing
% this function
[build_root,~,~] = fileparts (mfilename('fullpath'));
for build_configuration_index = 1:length (build_configurations)
    exe_dir = fullfile (build_root, build_configurations{build_configuration_index});
    
    if ~isfolder (exe_dir)
        mkdir (exe_dir);
    end
    
    % Compile the program.
    % a. The PATH is set to the MinGW directory as gcc needs to load some DLLs
    %    in the same directory.
    % b. The static pthread avoids DLL dependencies.
    % c. The -mno-ms-bitfields is required to get the size of the
    %    ethercat_frame_t structure correct which contains bit-fields spanning
    %    16-bits and 32-bit fields.
    % d. _POSIX_THREAD_SAFE_FUNCTIONS is defined to allow localtime_r() to be
    %    used.
    system(['set PATH=' mingw_path ';%PATH && ' ...
        gcc_exe ' -Wall -mno-ms-bitfields ' fullfile(build_root, 'switch_test_main.c') ...
        ' -D _POSIX_THREAD_SAFE_FUNCTIONS' ...
        ' -o '  fullfile(exe_dir,'switch_test.exe') ...
        ' -Wl,-Bstatic -lpthread -Wl,-Bdynamic ' ...
        ' ' npcap_options ...
        build_configuration_flags{build_configuration_index}]);
    
end
end