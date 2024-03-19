import os, contextlib
import subprocess
import argparse
import yaml

def get_arguments():
    parser = argparse.ArgumentParser(description='Image Manager: list and remove images')
    
    parser.add_argument('-ls', '--list', help='List all the images with the FUZZEVAL_TAG', action="store_true", required=False)
    parser.add_argument('-p', '--platforms', help='List all platform images with the FUZZEVAL_TAG', action="store_true", required=False)
    parser.add_argument('-fz', '--fuzzer', help='List all the fuzzer images with the FUZZEVAL_TAG', action="store_true", required=False)
    parser.add_argument('-fc', '--fuzz-campaign', help='List all the fuzzer-testharness campaign images with the FUZZEVAL_TAG', action="store_true", required=False)
    parser.add_argument('-rm', '--remove', help='Remove the image with the FUZZEVAL_TAG', required=False)
    parser.add_argument('-f', '--force', help='Force Remove the image with the FUZZEVAL_TAG', action="store_true", required=False)
    parser.add_argument('-rmall','--remove-all', help='Remove all the images with the FUZZEVAL_TAG', action="store_true", required=False)
    parser.add_argument('-dry', '--dry-run', help='Dry run. Do not remove anything', action="store_true", required=False)
    return parser.parse_args()


def list_images(tag, filter=None):
    proc1 = subprocess.Popen(['docker', 'image','ls'], stdout=subprocess.PIPE)
    proc2 = subprocess.Popen(['grep', tag], stdin=proc1.stdout,stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    proc1.stdout.close()
    
    out, err = proc2.communicate()
    all_images = [x for x in out.decode('utf-8').strip().split("\n") if x]
    if not all_images:
        print("No images found with the FUZZEVAL_TAG: {}".format(tag))
        exit(0)
    
    print("REPOSITORY                TAG        IMAGE ID       CREATED          SIZE")
    for t in all_images:
        _, filterTag = t.split()[:2]
        filterTag = filterTag.strip()
        if filter is None:
            print(t)
        else:
            if filterTag == filter:
                print(t)
    
def remove_image(tag, image, dry_run=False, force=False, filter=None):
    proc1 = subprocess.Popen(['docker', 'image','ls'], stdout=subprocess.PIPE)
    proc2 = subprocess.Popen(['grep', tag], stdin=proc1.stdout,stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    proc1.stdout.close()
    
    out, err = proc2.communicate()
    all_images = [x for x in out.decode('utf-8').strip().split("\n") if x]
    myimages = []
    
    foundImage = False
    imageToRemove = ""
    
    for t in all_images:
        name, filterTag = t.split()[:2]
        name = name.strip()
        filterTag = filterTag.strip()
        if filter is None:
            if image == name:
                imageToRemove = name+":"+filterTag
                foundImage = True
        else:
            if filterTag == filter:
                if image == name:
                    imageToRemove = name+":"+filterTag
                    foundImage = True
    
    if not foundImage:
        print("Image {} not found".format(image))
        exit(1)
    
    else:
        cmd = ['docker', 'image', 'rm']
        print("Removing image: {}".format(imageToRemove))
        if force:
            cmd.append('-f')
        cmd.append(imageToRemove)
        if not dry_run:
            subprocess.call(cmd)
        else:
            print("Dry run -- CMD: {}".format(cmd))
        

def remove_all(tag, dry_run=False, force=False, filter=None):
    proc1 = subprocess.Popen(['docker', 'image','ls'], stdout=subprocess.PIPE)
    proc2 = subprocess.Popen(['grep', tag], stdin=proc1.stdout,stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    proc1.stdout.close()
    
    out, err = proc2.communicate()
    all_images = [x for x in out.decode('utf-8').strip().split("\n") if x]
    myimages = []
    for t in all_images:
        name, filterTag = t.split()[:2]
        name = name.strip()
        filterTag = filterTag.strip()
        if filter is None:
            myimages.append(name+":"+filterTag)
        else:
            if filterTag == filter:
                myimages.append(name+":"+filterTag)
    
    cmd = ['docker', 'image', 'rm']
    
    # print(myimages)
    
    for image in myimages:
        print("Removing image: {}".format(image))
        if force:
            cmd.append('-f')
        cmd.append(image)
        if not dry_run:
            subprocess.call(cmd)
        else:
            print("Dry run -- CMD: {}".format(cmd))
        cmd = ['docker', 'image', 'rm']


def main():
    tagName="FUZZEVAL_TAG"
    
    tag = ""
    if tagName in os.environ:
        print("The FUZZEVAL_TAG is: {}".format(os.environ[tagName]))
        tag = os.environ[tagName]
    else:
        print("The FUZZEVAL_TAG is not set. Please set it and try again")
        exit(1)
    
    args = get_arguments()
    
    dry_run = args.dry_run
    force = args.force
    filter = None
    if args.platforms:
        filter = "platform"
    elif args.fuzzer:
        filter = "fuzzer"
    elif args.fuzz_campaign:
        filter = "campaign"
    
    if args.list:
        # dry run is ignored here
        if args.platforms:
            list_images(tag,filter)
        elif args.fuzzer:
            list_images(tag,filter)
        elif args.fuzz_campaign:
            list_images(tag,filter)
        else:
            list_images(tag)
    elif args.remove:
        remove_image(tag, args.remove, dry_run, force, filter)
    elif args.remove_all:
        remove_all(tag, dry_run, force, filter)
    else:
        print("Invalid arguments. Please use -h for help!")
        exit(1)

if __name__ == "__main__":
    main()