#!/usr/bin/env python
# -*- coding: utf-8 -*-
# vim:fenc=utf-8

# status: feature-complete

import jenkins
from retrying import retry
import logging
import json
from time import sleep
from dxmini.lib import CONSTANTS
logger = logging.getLogger(__name__)


class Jenkins(object):
    """a helper to run a jenkins job and return build status
    """
    def show_config(self, job, user, passw, jenkins_class_args=None):
        """Retrieves job XML config
        """
        if not jenkins_class_args:
            logging.info("Using default jenkins arguements from CONSTANTS")
            jenkins_class_args = CONSTANTS['jenkins']['main']['url']
        try:
            logging.debug("jenkins.Jenkins() ARGS".format(
                a=jenkins_class_args))
            url = jenkins_class_args['url']
            j = jenkins.Jenkins(url=url, username=user, password=passw)
        except Exception as e:
            logger.error("Exception! {}".format(e))
            exit(1)
        print(j.get_job_config(job))

    def build(self, job, params, jenkins_class_args=None, retries=20):
        """build a job with jenkins
        Arguments:
            job                    name of the jenkins job
            params                 dictionary of parameters for build
            jenkins_class_args     class arguements for jenkins.Jenkins()
                                   if None, internal CONSTANTS will be used
            retries                number of retries to wait for a pending job
                                   if it takes longer then this your executors
                                   are exausted
        Returns:
            boolean (true if job success, false if job failure)
        """
        self.job = job
        self.params = params
        self.retries = retries
        if not jenkins_class_args:
            logging.info("Using default jenkins arguements from CONSTANTS")
            jenkins_class_args = CONSTANTS['jenkins']['main']
        try:
            logging.debug("jenkins.Jenkins() ARGS".format(
                a=jenkins_class_args))
            self.jobinstance = jenkins.Jenkins(**jenkins_class_args)
        except Exception as e:
            logger.error("Exception! {}".format(e))
            exit(1)

        build_num = self._spawn_job()
        self._pending_job(build_num)
        self._poll_job(build_num)
        return self._job_result(build_num)

    def _validate_job_parameters(self, job, parameters):
        """
        validates a jenkins job parameters
        """
        try:
            valid_params = []
            if "parameterDefinitions" in self.jobinstance.get_job_info(job)["property"][0].keys():
                for definition in self.jobinstance.get_job_info(job)["property"][0]["parameterDefinitions"]:
                    valid_params.append(definition["name"])
                for parameter in parameters.keys():
                    if parameter not in valid_params:
                        error_message = "{} is not a valid parameter in {}.".format(
                            parameter, valid_params)
                        logging.error(error_message)
                        exit(1)
        except Exception as e:
            logger.error("Exception! {}".format(e))
            exit(1)

    def _spawn_job(self):
        """
        spawns a job in jenkins
        """
        if self.params == None:
            try:
                build_num = self.jobinstance.get_job_info(self.job)[
                    'nextBuildNumber']
                self.jobinstance.build_job(self.job)
            except Exception as e:
                logger.error("Exception! {}".format(e))
                exit(1)
        else:
            try:
                build_num = self.jobinstance.get_job_info(self.job)[
                    'nextBuildNumber']
            except Exception as e:
                logger.error("Exception! {}".format(e))
                exit(1)
            parameters = json.loads(self.params)
            self._validate_job_parameters(self.job, parameters)
            try:
                self.jobinstance.build_job(self.job, parameters)
            except Exception as e:
                logger.error("Exception! {}".format(e))
                exit(1)
        logger.info("{}: #{}...Requested".format(self.job, build_num))
        return build_num

    # print every 5 seconds, run for 1.8 days max
    @retry(stop_max_attempt_number=288, wait_fixed=500)
    def _pending_job(self, build_num):
        """
        notify when job is started
        """
        try:
            self.jobinstance.get_build_info(self.job, build_num)
            logger.info("{job}: #{buildnumber}...Job pending".format(
                job=self.job, buildnumber=build_num))
        except Exception as e:
            logger.error("Exception! {}".format(e))

    def _poll_job(self, build_num, delay=0):
        """
        notify when job is finished
        """
        building = True
        text = "Running"
        while building:
            delay += 2
            if not building:
                break
            try:
                building = self.jobinstance.get_build_info(
                    self.job, build_num)["building"]
            except Exception as e:
                logger.error("Exception! {}".format(e))
            if building:
                stext = "Job {text}".format(text=text)
            else:
                stext = "Job complete"
            logger.info("{}: #{}...{}".format(
                self.job, build_num, stext))
            if delay > 30:
                text = "Running (coffee time...)"
                delay = 0
            sleep(delay)

    def _job_result(self, build_num):
        """
        print job summary details
        """
        try:
            result = self.jobinstance.get_build_info(
                self.job, build_num)["result"]
        except Exception as e:
            logger.error("Exception! {}".format(e))
            exit(1)
        if result != "SUCCESS":
            error_message = "[{job}-#{buildnum}] Job completed with {status} status.".format(
                job=self.job, buildnum=build_num, status=result)
            logger.error(error_message)
            return False
        logger.info("{job}: #{buildnum}...{status}".format(
            job=self.job, buildnum=build_num, status=result))
        return True
