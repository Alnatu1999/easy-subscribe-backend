const express = require('express');
const router = express.Router();
const vtuService = require('../services/vtuService');

// Get TV variations
router.get('/tv-variations', async (req, res) => {
  try {
    const { provider } = req.query;
    
    if (!provider) {
      return res.status(400).json({
        success: false,
        message: 'Provider is required'
      });
    }
    
    // Map provider names to VTU service IDs
    let serviceId;
    switch (provider.toLowerCase()) {
      case 'dstv':
        serviceId = 'dstv';
        break;
      case 'gotv':
        serviceId = 'gotv';
        break;
      case 'startimes':
        serviceId = 'startimes';
        break;
      default:
        return res.status(400).json({
          success: false,
          message: 'Invalid provider'
        });
    }
    
    const variations = await vtuService.getTvVariations(serviceId);
    
    if (variations.code === 'success') {
      return res.json({
        success: true,
        data: variations.data
      });
    } else {
      return res.status(400).json({
        success: false,
        message: variations.message || 'Failed to fetch TV variations'
      });
    }
  } catch (error) {
    console.error('Error fetching TV variations:', error);
    return res.status(500).json({
      success: false,
      message: 'Server error'
    });
  }
});

// Verify TV customer
router.get('/tv-customer', async (req, res) => {
  try {
    const { provider, smartcard } = req.query;
    
    if (!provider || !smartcard) {
      return res.status(400).json({
        success: false,
        message: 'Provider and smartcard are required'
      });
    }
    
    // Map provider names to VTU service IDs
    let serviceId;
    switch (provider.toLowerCase()) {
      case 'dstv':
        serviceId = 'dstv';
        break;
      case 'gotv':
        serviceId = 'gotv';
        break;
      case 'startimes':
        serviceId = 'startimes';
        break;
      default:
        return res.status(400).json({
          success: false,
          message: 'Invalid provider'
        });
    }
    
    const customer = await vtuService.verifyCustomer(smartcard, serviceId);
    
    if (customer.code === 'success') {
      // Transform the response to match frontend expectations
      const customerData = {
        customerName: customer.data.Customer_Name || customer.data.customer_name || 'Not available',
        currentPlan: customer.data.Current_Package || customer.data.current_package || 'Not available'
      };
      
      return res.json({
        success: true,
        data: customerData
      });
    } else {
      return res.status(400).json({
        success: false,
        message: customer.message || 'Failed to verify customer'
      });
    }
  } catch (error) {
    console.error('Error verifying customer:', error);
    return res.status(500).json({
      success: false,
      message: 'Server error'
    });
  }
});

// Purchase TV subscription
router.post('/tv', async (req, res) => {
  try {
    const { provider, smartcard, plan, phone, email } = req.body;
    
    if (!provider || !smartcard || !plan || !phone) {
      return res.status(400).json({
        success: false,
        message: 'All fields are required'
      });
    }
    
    // Map provider names to VTU service IDs
    let serviceId;
    switch (provider.toLowerCase()) {
      case 'dstv':
        serviceId = 'dstv';
        break;
      case 'gotv':
        serviceId = 'gotv';
        break;
      case 'startimes':
        serviceId = 'startimes';
        break;
      default:
        return res.status(400).json({
          success: false,
          message: 'Invalid provider'
        });
    }
    
    // Generate a unique request ID
    const requestId = `TV-${Date.now()}-${Math.floor(Math.random() * 1000)}`;
    
    const result = await vtuService.purchaseTvSubscription(
      requestId,
      smartcard,
      serviceId,
      plan
    );
    
    if (result.code === 'success') {
      // Transform the response to match frontend expectations
      const transactionData = {
        reference: result.request_id || requestId,
        provider: provider,
        smartcard: smartcard,
        status: result.status || 'success',
        amount: result.amount || 0,
        createdAt: new Date().toISOString()
      };
      
      return res.json({
        success: true,
        data: transactionData,
        message: result.message || 'TV subscription successful'
      });
    } else {
      return res.status(400).json({
        success: false,
        message: result.message || 'Failed to purchase TV subscription'
      });
    }
  } catch (error) {
    console.error('Error purchasing TV subscription:', error);
    return res.status(500).json({
      success: false,
      message: 'Server error'
    });
  }
});

module.exports = router;