#!/bin/bash
# Loop over all directories in the current directory
for dir in */; do
    if [ -d "$dir" ]; then
        echo "============Entering $dir============"
        pushd "$dir"
        if [ -e "Dockerfile" ] && [ -e "build.sh" ]; then
			echo "Building $dir"
			./build.sh
        else
            echo "No Dockerfile or build.sh in $dir"
			echo "Skipping $dir"
        fi
        echo "============Exiting $dir============"
        echo ""
        popd
        # You can perform actions on each directory here
    fi
done
