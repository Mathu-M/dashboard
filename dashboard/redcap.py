from __future__ import absolute_import

from config import REDCAP_TOKEN
import redcap as REDCAP
from .models import Session, Study, Site
from . import utils
from urlparse import urlparse
import logging
import datman.scanid
import requests

logger = logging.getLogger(__name__)

class redcap_exception(Exception):
    """Generic error for recap interface"""


class redcap_record(object):
    """
    Represents a record in a redcap database
    Can be created from a request object generated by the recap API callback
    """

    redcap_url = None
    record_id = None
    study = None
    date = None
    comment = None
    session_name = None
    instrument = None
    rc_user = None
    instrument_completed = False
    redcap_record = None

    def __init__(self, request=None):
        if request:
            self.create_from_request(request)

    def create_from_request(self, request):
        try:
            self.redcap_url = request.form['redcap_url']
            self.record_id = request.form['record']
            self.instrument = request.form['instrument']
            self.project_id = request.form['project_id']

            if int(request.form[self.instrument + '_complete']) == 2:
                self.instrument_completed = True
        except KeyError:
            raise redcap_exception('Required key not found in request object.'
                                   '{}'.format(request.form.keys()))

        try:
            rc = REDCAP.Project(self.redcap_url + 'api/', REDCAP_TOKEN)
            redcap_record = rc.export_records([self.record_id])

            if len(redcap_record) < 0:
                raise redcap_exception('Record:{} not found in redcap'
                                       .format(self.record_id))
            elif len(redcap_record) > 1:
                raise redcap_exception('Record:{} is not unique in redcap'
                                       .format(self.record_id))
            else:
                self.redcap_record = redcap_record[0]

        except REDCAP.RedcapError as e:
            raise e

        try:
            self.date = self.redcap_record['date']
            self.comment = self.redcap_record['cmts']
            self.rc_user = self.redcap_record['ra_id']
            self.__set_session(self.redcap_record['par_id'])
        except KeyError:
            raise redcap_exception('Required field not found in recap record.'
                                   '{}'.format(self.redcap_record.keys()))

    def __set_session(self, name):
        str_session = name.upper()
        try:
            ident = datman.scanid.parse(str_session)
        except datman.scanid.ParseException:
            msg = 'Invalid session id:{}.'.format(str_session)
            logger.error(msg)
            raise redcap_exception(msg)

        str_session = ident.get_full_subjectid_with_timepoint()

        db_session = Session.query.filter(Session.name == str_session)

        if db_session.count() < 1:
            # going to create a new session record

            self.__set_site(ident.site)
            self.__set_study(ident.study)

            db_session = Session()
            db_session.name = str_session
            db_session.study = self.db_study
            db_session.site = self.db_site
            db_session.is_phantom = datman.scanid.is_phantom(ident)

            if ident.session:
                db_session.repeat_count = int(ident.session)
            if int(ident.session) > 1:
                db_session.is_repeated = True
            else:
                db_session.is_repeated = False

        elif db_session.count() > 1:
            raise redcap_exception('Failed to uniquely identify session {}'
                                   .format(self.session_name))
        else:
            db_session = db_session.first()
            self.__set_study(db_session.study)
            self.__set_site(db_session.site)
        #update the module globals
        self.db_session = db_session


    def __set_site(self, site):
        """
        Set the site from session string
        """
        site_str = site.upper()

        db_site = Site.query.filter(Site.name == site_str)

        if db_site.count() != 1:
            msg = 'Failed to identify site:{} in database'.format(site_str)
            logger.error(msg)
            raise redcap_exception(msg)
        else:
            self.db_site = db_site.first()
            logger.debug('Setting site to:{}.'
                         .format(self.db_site.name))

    def __set_study(self, study_str):
        """
        Set the study from the id in the session name
        """
        if not utils._check_study(study_str):
            study_str = utils.get_study_name(study_str)

        db_study = Study.query.filter(Study.nickname == study_str)

        if db_study.count() != 1:
            msg = 'Failed to identify study:{} in database'.format(study_str)
            logger.error(msg)
            raise redcap_exception(msg)
        else:
            self.db_study = db_study.first()
            logger.debug('Setting study to:{}.'
                         .format(self.db_study.nickname))

    def update_db_session(self):
        if not self.db_session:
            raise redcap_exception('Session not set')

        try:
            self.db_session.redcap_record = self.record_id
            self.db_session.redcap_url = self.redcap_url
            self.db_session.redcap_entry_date = self.date
            self.db_session.redcap_user = self.rc_user
            self.db_session.redcap_comment = self.comment
            self.db_session.redcap_instrument = self.instrument
            self.db_session.redcap_projectid = self.project_id
            self.db_session.flush_changes()
        except Exception as e:
            logger.debug(str(e))
            raise redcap_exception('Failed to update session object')

    def get_survey_return_code(self):
        url = self.redcap_url + 'api/'
        payload = {'token': REDCAP_TOKEN,
                   'format': 'json',
                   'record': self.record_id,
                   'instrument': self.instrument,
                   'content': 'surveyLink'}
        response = requests.post(url, data=payload)
        logger.info(str(response.text))