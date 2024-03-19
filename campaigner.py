import os, contextlib
import subprocess
import argparse
import yaml


def image_exists(image):
    proc1 = subprocess.Popen(['docker', 'image','ls', image], stdout=subprocess.PIPE)
    out,err = proc1.communicate()    
    all_images = [x for x in out.decode('utf-8').strip().split("\n") if x]
    myimages = []
    for t in all_images:
        myimages.append(t.split()[0].strip()+":"+t.split()[1].strip())
    return image in myimages

@contextlib.contextmanager
def pushd(new_dir):
    previous_dir = os.getcwd()
    os.chdir(new_dir)
    try:
        yield
    finally:
        os.chdir(previous_dir)

def parse_cmds():
    parser = argparse.ArgumentParser()
    parser.add_argument('--build-all', '-all', action='store_true', required=False)
    parser.add_argument('--fuzzer', '-f', type=str, required=False)
    parser.add_argument('--testsubject', '-t', type=str, required=False)
    parser.add_argument('--config-path', '-c', type=str, required=False, default=None)
    parser.add_argument('--dry-run', '-d', action='store_true', required=False)
    parser.add_argument('--run', '-r', action='store_true', required=False) # also runs the campaign in background
    return parser.parse_args()

def build_image(BASE_IMAGE, testSubjectDict, NEW_IMAGE, dryrun=False):
    if not image_exists(BASE_IMAGE):
        print("The base image {} does not exist. Please build it and try again".format(BASE_IMAGE))
        exit(1)
    with pushd(testSubjectDict['path']):
        print("BUILDING DOCKER IMAGE")
        print(['docker', 'build','--no-cache',
                '--build-arg=baseimage={}'.format(BASE_IMAGE),
                '--build-arg=fc_configpath={}'.format(testSubjectDict['fc_configpath']),
                '--build-arg=harness_dir={}'.format(testSubjectDict['harnessdir']), 
                '-t', NEW_IMAGE, 
                '-f', 'Dockerfile', '.'])
        if not dryrun:
            subprocess.run(['docker', 'build','--no-cache', 
                '--build-arg=baseimage={}'.format(BASE_IMAGE),
                '--build-arg=fc_configpath={}'.format(testSubjectDict['fc_configpath']),
                '--build-arg=harness_dir={}'.format(testSubjectDict['harnessdir']), 
                '-t', NEW_IMAGE, 
                '-f', 'Dockerfile', '.'])
            
    print("DOCKER IMAGE IS READY!!: {}".format(NEW_IMAGE))
    print("TO RUN THE DOCKER IMAGE, USE THE FOLLOWING COMMAND:")
    print("docker run -td --rm -v {}:/Results -v {}:/Config --privileged --name {} {}".format("PATH_TO_RESULTS", "PATH_TO_CONFIG", NEW_IMAGE, NEW_IMAGE))
    
    

def runImage(IMAGE_NAME, RESULTSPATH, CONFIGPATH, CPUSET=None, MEMORY=None, dryrun=False, INTERACTIVE=False):
    curDir = os.getcwd()
    runningmode = '-td'
    if INTERACTIVE:
        runningmode = '-it'
    pre = [
        'docker', 
        'run',
        '-e','HOST_UID={}'.format(os.getuid()),
        '-e', 'HOST_GID={}'.format(os.getgid()),
        '{}'.format(runningmode), '--rm',
        '-v', '{}:/Results'.format(curDir+os.sep+RESULTSPATH),
        '-v', '{}:/Config'.format(curDir+os.sep+CONFIGPATH),
    ]
    if MEMORY is not None:
        pre.append('--memory={}'.format(MEMORY))
    if CPUSET is not None:
        pre.append('--cpuset-cpus={}'.format(CPUSET))

    post = ['--privileged',
            '--name', '{}'.format(IMAGE_NAME.replace("/","-").replace(":","-")),
            '{}'.format(IMAGE_NAME)  
            ]
    
    print(pre + post)
    if dryrun:
        print(pre + post)
    else:
        subprocess.run(pre + post)

def main():
    
    tagName="FUZZEVAL_TAG"
    
    tag = ""
    if tagName in os.environ:
        print("The FUZZEVAL_TAG is: {}".format(os.environ[tagName]))
        tag = os.environ[tagName]
    else:
        print("The FUZZEVAL_TAG is not set. Please set it and try again")
        exit(1)
    
    args = parse_cmds()
    fuzzer = args.fuzzer
    testsubject = args.testsubject
    build_all = args.build_all
    fuzz_config = None
    CONFIGPATH = args.config_path
    
    # STEP 1: Get the list of campaigns to build
    campaigns_to_build = []
    if CONFIGPATH == None:
        if not fuzzer and not testsubject and not build_all:
            print("Please specify a fuzzer or testsubject or use the --build-all flag")
            exit(1)
        
        if build_all:
            confpath = os.path.join(os.path.dirname(os.path.realpath(__file__)), "ImageConf")
            extension = ".yaml"
            tmp_config = {}
            for file in os.listdir(confpath):
                if file.endswith(extension):
                    with open(os.path.join(confpath, file), 'r') as f:
                        tmp_config = yaml.load(f.read(), Loader=yaml.FullLoader)
                        assert tmp_config is not None
                        for fuzzer in tmp_config.keys():
                            for testsubject in tmp_config[fuzzer]['testsubjects'].keys():
                                campaigns_to_build.append(tmp_config[fuzzer]['testsubjects'][testsubject])
        
        elif fuzzer and testsubject: # build a specific campaign
            CONFIGPATH=os.path.join(os.path.dirname(os.path.realpath(__file__)), "ImageConf", "{}.yaml".format(fuzzer))
            with open(CONFIGPATH, 'r') as f:
                fuzz_config = yaml.load(f.read(), Loader=yaml.FullLoader)
            assert fuzz_config is not None
            
            if testsubject not in fuzz_config[fuzzer]['testsubjects'].keys():
                print('Testsubject not available for {}'.format(fuzzer))
                exit(1)
            else:
                campaigns_to_build.append(fuzz_config[fuzzer]['testsubjects'][testsubject])
        
        elif fuzzer: # build all testsubjects campaigns for the fuzzer
            CONFIGPATH=os.path.join(os.path.dirname(os.path.realpath(__file__)), "ImageConf", "{}.yaml".format(fuzzer))
            with open(CONFIGPATH, 'r') as f:
                fuzz_config = yaml.load(f.read(), Loader=yaml.FullLoader)
            assert fuzz_config is not None
            for testsubject in fuzz_config[fuzzer]['testsubjects'].keys():
                campaigns_to_build.append(fuzz_config[fuzzer]['testsubjects'][testsubject])
        
        elif testsubject: # build all fuzzers campaigns for the testsubject
            confpath = os.path.join(os.path.dirname(os.path.realpath(__file__)), "ImageConf")
            extension = ".yaml"
            tmp_config = {}
            for file in os.listdir(confpath):
                if file.endswith(extension):
                    with open(os.path.join(confpath, file), 'r') as f:
                        tmp_config = yaml.load(f.read(), Loader=yaml.FullLoader)
                        assert tmp_config is not None
                        for fuzzer in tmp_config.keys():
                            if testsubject in tmp_config[fuzzer]['testsubjects'].keys():
                                campaigns_to_build.append(tmp_config[fuzzer]['testsubjects'][testsubject])

    else:    
        # Check if the fuzz-config.yaml file exists and fuzzer, testsubject are specified or build-all is set
        if not os.path.exists(CONFIGPATH):
            raise FileNotFoundError('{} file not found'.format(CONFIGPATH))
        # Read the fuzz-config.yaml file
        with open(CONFIGPATH, 'r') as f:
            fuzz_config = yaml.load(f.read(), Loader=yaml.FullLoader)
        assert fuzz_config is not None
        ## Assumes that all campaigns are to be built for the given config file: i.e. build_all by default for the given config file
        if fuzzer and testsubject:
            if fuzzer not in fuzz_config.keys():
                raise NotImplementedError('Fuzzer not in {}.yaml'.format(CONFIGPATH))
            testsubjects = fuzz_config[fuzzer]['testsubjects']
            if testsubject not in testsubjects.keys():
                raise NotImplementedError(
                    'Testsubject "{}" not in {}.yaml'.format(testsubject, CONFIGPATH))
            campaigns_to_build.append(testsubjects[testsubject])
        elif fuzzer:
            if fuzzer not in fuzz_config.keys():
                raise NotImplementedError('Fuzzer not in {}.yaml'.format(CONFIGPATH))
            testsubjects = fuzz_config[fuzzer]['testsubjects']
            for testsubject in testsubjects.keys():
                campaigns_to_build.append(testsubjects[testsubject])
        elif testsubject:
            for fuzzer in fuzz_config.keys():
                testsubjects = fuzz_config[fuzzer]['testsubjects']
                if testsubject in testsubjects.keys():
                    campaigns_to_build.append(testsubjects[testsubject])
        else: # build all by default
            for fuzzer in fuzz_config.keys():
                testsubjects = fuzz_config[fuzzer]['testsubjects']
                for testsubject in testsubjects.keys():
                    campaigns_to_build.append(testsubjects[testsubject])
    
    
    # STEP 2: use the list of campaigns to build to build the images
    for testSubjectDict in campaigns_to_build:        
        BASE_IMAGE = tag+"/"+testSubjectDict['baseimage']+":fuzzer"
        NEW_IMAGE = tag+"/"+testSubjectDict['image_name']+":campaign"
        
            # STEP 2.1: build the image 
        build_image(BASE_IMAGE, testSubjectDict, NEW_IMAGE, args.dry_run)
        if args.run:    
            RESULTSPATH=testSubjectDict['resultsdir']
            CONFIGPATH=testSubjectDict['configdir']
            MEMORY=testSubjectDict['memory'] if 'memory' in testSubjectDict else None
            CPUSET=testSubjectDict['cpuset'] if 'cpuset' in testSubjectDict else None
            DRYRUN=args.dry_run
            INTERACTIVE=False
            IMAGE_NAME = NEW_IMAGE
            # STEP 2.2: Optionally run the image
            if image_exists(IMAGE_NAME):
                runImage(IMAGE_NAME, RESULTSPATH, CONFIGPATH, CPUSET, MEMORY, DRYRUN, INTERACTIVE)

if __name__ == '__main__':
    main()
