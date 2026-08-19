import { getConfig } from '../../common/config/config';
import { maskToken } from '../../common/utils/token';
import { log as logger } from '../../../logs/logger';
import { PostFilterPreparedRequest } from '../../../broker-workload/prepareRequest';
import { makeSingleRawRequestToDownstream } from '../../http/request';
import { sanitizeRequestUrl } from '../../http/urlValidation';

export const validateBrokerClientCredentials = async (
  authHeaderValue: string,
  brokerClientId: string,
  brokerConnectionIdentifier: string,
  isInternalJwt = false,
) => {
  if (!/^[a-zA-Z0-9._-]+$/.test(brokerConnectionIdentifier)) {
    return false;
  }
  const body = {
    data: {
      type: 'broker_connection',
      attributes: {
        broker_client_id: brokerClientId,
      },
    },
  };

  const serviceHostname = isInternalJwt
    ? `${getConfig().authorizationService}`
    : `${getConfig().apiHostname}`;
  const req: PostFilterPreparedRequest = {
    url: sanitizeRequestUrl(`${serviceHostname}/hidden/brokers/connections/${encodeURIComponent(brokerConnectionIdentifier)}/auth/validate?version=2024-02-08~experimental`),
    headers: {
      authorization: authHeaderValue,
      'Content-type': 'application/vnd.api+json',
    },
    method: 'POST',
    body: JSON.stringify(body),
  };
  const response = await makeSingleRawRequestToDownstream(req);
  logger.debug(
    {
      maskedToken: maskToken(brokerConnectionIdentifier),
      validationResponseCode: response.statusCode,
    },
    'Validate Broker Client Credentials response',
  );
  if (response.statusCode === 201) {
    return true;
  } else {
    logger.debug(
      { statusCode: response.statusCode, message: response.statusText },
      `Broker ${brokerConnectionIdentifier} client ID ${brokerClientId} failed validation.`,
    );
    return false;
  }
};
