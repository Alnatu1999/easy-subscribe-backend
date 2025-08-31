// services/vtuService.js
const axios = require('axios');
const crypto = require('crypto');

// VTU.ng API configuration
const VTU_BASE_URL = 'https://vtu.ng/wp-json';
const VTU_AUTH_URL = `${VTU_BASE_URL}/jwt-auth/v1/token`;
const VTU_API_URL = `${VTU_BASE_URL}/api/v2`;

// Store credentials securely (use environment variables in production)
const VTU_USERNAME = process.env.VTU_USERNAME || 'your_vtu_username';
const VTU_PASSWORD = process.env.VTU_PASSWORD || 'your_vtu_password';
const VTU_USER_PIN = process.env.VTU_USER_PIN || 'your_user_pin';

// Cache for access token
let accessToken = null;
let tokenExpiry = null;

// Get access token from VTU.ng
async function getAccessToken() {
  // Check if we have a valid token
  if (accessToken && tokenExpiry && new Date() < tokenExpiry) {
    return accessToken;
  }
  try {
    const response = await axios.post(VTU_AUTH_URL, {
      username: VTU_USERNAME,
      password: VTU_PASSWORD
    });
    if (response.data.token) {
      accessToken = response.data.token;
      // Token expires after 7 days, set expiry to 6 days for safety
      tokenExpiry = new Date(Date.now() + 6 * 24 * 60 * 60 * 1000);
      return accessToken;
    } else {
      throw new Error('Failed to get access token');
    }
  } catch (error) {
    console.error('VTU Authentication Error:', error.response?.data || error.message);
    throw new Error('Authentication with VTU.ng failed');
  }
}

// Validate smartcard format based on provider
function validateSmartcardFormat(smartcard, provider) {
  if (!smartcard || typeof smartcard !== 'string') {
    return { valid: false, message: 'Smartcard number is required' };
  }
  
  // Remove any spaces or dashes
  const cleanCard = smartcard.replace(/[\s-]/g, '');
  
  // Provider-specific validation
  switch (provider.toLowerCase()) {
    case 'dstv':
      if (!/^\d{10,11}$/.test(cleanCard)) {
        return { valid: false, message: 'DStv smartcard must be 10-11 digits' };
      }
      break;
    case 'gotv':
      if (!/^\d{10}$/.test(cleanCard)) {
        return { valid: false, message: 'GOtv smartcard must be 10 digits' };
      }
      break;
    case 'startimes':
      if (!/^\d{10,12}$/.test(cleanCard)) {
        return { valid: false, message: 'StarTimes smartcard must be 10-12 digits' };
      }
      break;
    default:
      // Generic validation for unknown providers
      if (!/^\d{8,15}$/.test(cleanCard)) {
        return { valid: false, message: 'Invalid smartcard number format' };
      }
  }
  
  return { valid: true, message: 'Valid format' };
}

// Get TV variations (public endpoint, no auth required)
async function getTvVariations(serviceId = null) {
  try {
    let url = `${VTU_API_URL}/variations/tv`;
    if (serviceId) {
      url += `?service_id=${serviceId}`;
    }
    const response = await axios.get(url);
    return response.data;
  } catch (error) {
    console.error('Error fetching TV variations:', error.response?.data || error.message);
    throw new Error('Failed to fetch TV variations');
  }
}

// Verify customer (smartcard/IUC number)
async function verifyCustomer(customerId, serviceId) {
  // First, validate the format locally
  const formatValidation = validateSmartcardFormat(customerId, serviceId);
  if (!formatValidation.valid) {
    return {
      code: 'error',
      message: formatValidation.message
    };
  }
  
  try {
    const token = await getAccessToken();
    
    const response = await axios.post(
      `${VTU_API_URL}/verify-customer`,
      {
        customer_id: customerId,
        service_id: serviceId
      },
      {
        headers: {
          'Authorization': `Bearer ${token}`,
          'Content-Type': 'application/json'
        }
      }
    );
    return response.data;
  } catch (error) {
    console.error('Error verifying customer:', error.response?.data || error.message);
    
    // Provide more specific error messages based on the error
    if (error.response && error.response.data) {
      const vtuError = error.response.data;
      
      if (vtuError.message && vtuError.message.toLowerCase().includes('invalid')) {
        return {
          code: 'error',
          message: 'Invalid smartcard number'
        };
      } else if (vtuError.message && vtuError.message.toLowerCase().includes('not found')) {
        return {
          code: 'error',
          message: 'Smartcard not found'
        };
      } else if (vtuError.message && vtuError.message.toLowerCase().includes('does not exist')) {
        return {
          code: 'error',
          message: 'Smartcard does not exist'
        };
      }
    }
    
    return {
      code: 'error',
      message: 'Failed to verify customer details'
    };
  }
}

// Purchase TV subscription
async function purchaseTvSubscription(requestId, customerId, serviceId, variationId, subscriptionType = 'change') {
  try {
    // Validate smartcard format before making the purchase
    const formatValidation = validateSmartcardFormat(customerId, serviceId);
    if (!formatValidation.valid) {
      return {
        code: 'error',
        message: formatValidation.message
      };
    }
    
    const token = await getAccessToken();
    
    const response = await axios.post(
      `${VTU_API_URL}/tv`,
      {
        request_id: requestId,
        customer_id: customerId,
        service_id: serviceId,
        variation_id: variationId,
        subscription_type: subscriptionType
      },
      {
        headers: {
          'Authorization': `Bearer ${token}`,
          'Content-Type': 'application/json'
        }
      }
    );
    return response.data;
  } catch (error) {
    console.error('Error purchasing TV subscription:', error.response?.data || error.message);
    
    // Provide more specific error messages based on the error
    if (error.response && error.response.data) {
      const vtuError = error.response.data;
      
      if (vtuError.message && vtuError.message.toLowerCase().includes('invalid customer')) {
        return {
          code: 'error',
          message: 'Invalid smartcard number'
        };
      } else if (vtuError.message && vtuError.message.toLowerCase().includes('insufficient balance')) {
        return {
          code: 'error',
          message: 'Insufficient balance for this subscription'
        };
      }
    }
    
    return {
      code: 'error',
      message: 'Failed to purchase TV subscription'
    };
  }
}

// Requery order status
async function requeryOrder(requestId) {
  try {
    const token = await getAccessToken();
    
    const response = await axios.post(
      `${VTU_API_URL}/requery`,
      {
        request_id: requestId
      },
      {
        headers: {
          'Authorization': `Bearer ${token}`,
          'Content-Type': 'application/json'
        }
      }
    );
    return response.data;
  } catch (error) {
    console.error('Error requerying order:', error.response?.data || error.message);
    throw new Error('Failed to requery order status');
  }
}

// Verify webhook signature
function verifyWebhookSignature(payload, signature) {
  const computedSignature = crypto
    .createHmac('sha256', VTU_USER_PIN)
    .update(JSON.stringify(payload))
    .digest('hex');
  
  return crypto.timingSafeEqual(
    Buffer.from(computedSignature, 'hex'),
    Buffer.from(signature, 'hex')
  );
}

module.exports = {
  getAccessToken,
  getTvVariations,
  verifyCustomer,
  purchaseTvSubscription,
  requeryOrder,
  verifyWebhookSignature,
  validateSmartcardFormat  // Export the validation function for use in other modules
};