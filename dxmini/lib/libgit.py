#!/usr/bin/env python
# -*- coding: utf-8 -*-
# vim:fenc=utf-8

# status: feature-complete

import subprocess
import os
import logging
from shutil import rmtree
from random import choice
from string import ascii_lowercase
from dxmini.lib import CONSTANTS
from git.exc import GitCommandError
from uuid import uuid4
import git

logger = logging.getLogger(__name__)

class Directory(object):
    """
    context handler to jump in and out of a directory per context block
    handles state of new CWD and returns to old CWD on __exit__
    similar to the bash push/pop in which you return to the previous CWD
    after changing directory contexts, use multiple contexts to make a stack
    """

    def __init__(self, path):
        self.path = path
        self.start_dir = os.getcwd()

    def __enter__(self):
        os.chdir(self.path)
        logger.info("Entering directory: {}".format(os.getcwd()))
        return self

    def __exit__(self, type, value, traceback):
        os.chdir(self.start_dir)
        logger.info("Exiting directory: {}".format(os.getcwd()))
        return self

class GitCrud(object):
    """
    class to update a file from git and push to master
    """
    def __init__(self, repo):
        """
        init
        """
        self.repo_url = repo
        smalluuid = str(uuid4()).split('-')[4]
        self.tmp = "tmp_{}".format(smalluuid)
        try:
            self.repo_obj = git.Repo.clone_from(self.repo_url, self.tmp, branch="master")
        except Exception as e:
            logger.error("Failure to clone: {}".format(repo))
            logger.error("Exception: {}".format(e))
            exit(1)

    def update_file(self, new_content, filename):
        """
        updates a git file with new file contents
        """
        try:
            with open(filename, "w") as f:
                f.write(new_content)
        except Exception as e:
            logger.error("Cannot open file for writing: {}".format(filename))
            logger.error("Exception: {}".format(e))
            self.close()
            exit(1)
        self.add_file(filename)

    def checkout(self, branch, flag=None):
        """
        perform a checkout command
        """
        if flag:
            try:
                self.repo_obj.git.checkout(flag, branch)
            except Exception as e:
                logger.error("Failure to checkout: {}".format(branch))
                logger.error("Exception: {}".format(e))
                self.close()
                exit(1)
        else:
            try:
                self.repo_obj.git.checkout(flag, branch)
            except Exception as e:
                logger.error("Failure to checkout: {}".format(branch))
                logger.error("Exception: {}".format(e))
                self.close()
                exit(1)

    def add_file(self, filename):
        """
        adds a file to git index
        """
        try:
            self.repo_obj.index.add([filename])
        except Exception as e:
            logger.error("Failure add: {}".format(filename))
            logger.error("Exception: {}".format(e))
            self.close()
            exit(1)

    def branch_exists(self, branch):
        """
        return true if branch exist
        """
        remote_branches = []
        try:
            for ref in self.repo_obj.git.branch('-r').split('\n'):
                remote_branches.append(ref.strip())
            if 'origin/{}'.format(branch) in remote_branches:
                return True
            else:
                return False
        except Exception as e:
            logger.error("Failure to verify branch {}".format(branch))
            logger.error("Exception: {}".format(e))
            self.close()
            exit(1)

    def commit(self, branch=None, message=None):
        """
        commits changes back to master
        """
        if not message:
            message = "AutoCommit using GitCrud class"

        self.repo_obj.index.commit(message)
        self.origin = self.repo_obj.remote('origin')
        if self.branch_exists(branch):
            raise NotImplementedError("I dont dunno how to make multiple commits to a secondary branch yet")
            # why doesnt this obvious command work??????????????????
            #self.repo_obj.git.checkout(branch)
            #self.origin.push(branch)
        else:
            self.repo_obj.git.checkout('-b', branch)
            try:
                self.origin.push(branch)
            except Exception as e:
                logger.error("Failure to push branch: {}".format(branch))
                logger.error("Exception: {}".format(e))
                self.close()
                exit(1)
        if not branch:
            try:
                self.origin.push()
            except Exception as e:
                logger.error("Failure to push")
                logger.error("Exception: {}".format(e))
                self.close()
                exit(1)
        self.close()

    def close(self):
        """
        cleanup
        """
        try:
            rmtree(self.tmp)
        except Exception as e:
            logger.error("Could not remove temp directory")
            logger.info("Must delete this file manually: {}".format(self.tmp))
            logger.error("Exception: {}".format(e))
            exit(1)
