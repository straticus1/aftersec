"use client"

import React, { useEffect, useState } from 'react'
import { ArrowUpCircle, Zap, Shield, Brain } from 'lucide-react'

interface TierInfo {
  current_tier: string
  tier_level: number
  ai_budget: {
    daily_limit_usd: number
    monthly_limit_usd: number
    daily_used_usd: number
    monthly_used_usd: number
    daily_remaining_usd: number
    monthly_remaining_usd: number
    percent_used: number
    is_byok: boolean
  }
  dark_web_features: Record<string, boolean>
  max_ai_models: number
  upgrade_options: Array<{
    target_tier: string
    price_per_month: number
    description: string
    features: string[]
  }>
}

export default function TierStatusBanner({ orgId }: { orgId: string }) {
  const [tierInfo, setTierInfo] = useState<TierInfo | null>(null)
  const [loading, setLoading] = useState(true)
  const [showUpgradeModal, setShowUpgradeModal] = useState(false)

  useEffect(() => {
    fetchTierInfo()
  }, [orgId])

  const fetchTierInfo = async () => {
    try {
      const response = await fetch(`/api/v1/organizations/tier?org_id=${orgId}`, {
        headers: {
          'Authorization': `Bearer ${localStorage.getItem('jwt_token')}`
        }
      })
      if (response.ok) {
        const data = await response.json()
        setTierInfo(data)
      }
    } catch (error) {
      console.error('Failed to fetch tier info:', error)
    } finally {
      setLoading(false)
    }
  }

  const handleUpgrade = async (targetTier: string) => {
    try {
      const response = await fetch('/api/v1/organizations/upgrade', {
        method: 'POST',
        headers: {
          'Authorization': `Bearer ${localStorage.getItem('jwt_token')}`,
          'Content-Type': 'application/json'
        },
        body: JSON.stringify({
          organization_id: orgId,
          target_tier: targetTier,
          payment_method_id: 'mock_payment_method' // TODO: Integrate Stripe
        })
      })

      if (response.ok) {
        await fetchTierInfo()
        setShowUpgradeModal(false)
        alert('Successfully upgraded tier!')
      } else {
        const error = await response.json()
        alert('Upgrade failed: ' + error.message)
      }
    } catch (error) {
      console.error('Upgrade error:', error)
      alert('Upgrade failed')
    }
  }

  if (loading || !tierInfo) {
    return null
  }

  const getTierColor = (tier: string) => {
    switch (tier.toLowerCase()) {
      case 'basic':
        return 'bg-gray-800 border-gray-700'
      case 'professional':
        return 'bg-blue-900/30 border-blue-600'
      case 'enterprise':
        return 'bg-purple-900/30 border-purple-600'
      default:
        return 'bg-gray-800 border-gray-700'
    }
  }

  const getTierBadge = (tier: string) => {
    switch (tier.toLowerCase()) {
      case 'basic':
        return <span className="px-2 py-1 text-xs bg-gray-700 text-gray-300 rounded">FREE</span>
      case 'professional':
        return <span className="px-2 py-1 text-xs bg-blue-600 text-white rounded">PRO</span>
      case 'enterprise':
        return <span className="px-2 py-1 text-xs bg-purple-600 text-white rounded">ENTERPRISE</span>
      default:
        return null
    }
  }

  const budgetPercentColor = tierInfo.ai_budget.percent_used > 80
    ? 'bg-red-500'
    : tierInfo.ai_budget.percent_used > 60
    ? 'bg-yellow-500'
    : 'bg-green-500'

  return (
    <>
      <div className={`border rounded-lg p-4 ${getTierColor(tierInfo.current_tier)}`}>
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-4">
            <div>
              <div className="flex items-center gap-2 mb-1">
                <Shield className="w-5 h-5 text-cyan-400" />
                <span className="text-sm text-gray-400">License Tier</span>
                {getTierBadge(tierInfo.current_tier)}
              </div>
              <h3 className="text-lg font-semibold text-white capitalize">
                {tierInfo.current_tier}
              </h3>
            </div>

            {!tierInfo.ai_budget.is_byok && (
              <div className="border-l border-gray-700 pl-4">
                <div className="flex items-center gap-2 mb-1">
                  <Brain className="w-5 h-5 text-purple-400" />
                  <span className="text-sm text-gray-400">AI Budget</span>
                </div>
                <div className="flex items-center gap-2">
                  <div className="w-32 bg-gray-700 rounded-full h-2">
                    <div
                      className={`h-2 rounded-full transition-all ${budgetPercentColor}`}
                      style={{ width: `${Math.min(tierInfo.ai_budget.percent_used, 100)}%` }}
                    />
                  </div>
                  <span className="text-sm text-white font-mono">
                    ${tierInfo.ai_budget.monthly_used_usd.toFixed(2)} / ${tierInfo.ai_budget.monthly_limit_usd.toFixed(2)}
                  </span>
                </div>
              </div>
            )}

            {tierInfo.ai_budget.is_byok && (
              <div className="border-l border-gray-700 pl-4">
                <div className="flex items-center gap-2">
                  <Zap className="w-5 h-5 text-yellow-400" />
                  <span className="text-sm text-gray-300">BYOK Mode</span>
                </div>
                <p className="text-xs text-gray-500">Bring Your Own API Key</p>
              </div>
            )}

            {tierInfo.max_ai_models > 1 && (
              <div className="border-l border-gray-700 pl-4">
                <div className="flex items-center gap-2">
                  <Brain className="w-5 h-5 text-purple-400" />
                  <span className="text-sm text-gray-300">SWARM Mode</span>
                </div>
                <p className="text-xs text-gray-500">{tierInfo.max_ai_models} AI Models</p>
              </div>
            )}
          </div>

          {tierInfo.upgrade_options.length > 0 && (
            <button
              onClick={() => setShowUpgradeModal(true)}
              className="flex items-center gap-2 px-4 py-2 bg-gradient-to-r from-cyan-500 to-blue-500 hover:from-cyan-600 hover:to-blue-600 text-white rounded-lg transition-all"
            >
              <ArrowUpCircle className="w-4 h-4" />
              Upgrade
            </button>
          )}
        </div>
      </div>

      {showUpgradeModal && (
        <div className="fixed inset-0 bg-black/80 flex items-center justify-center z-50 p-4">
          <div className="bg-gray-900 border border-gray-700 rounded-lg max-w-4xl w-full p-6">
            <div className="flex items-center justify-between mb-6">
              <h2 className="text-2xl font-bold text-white">Upgrade Your Tier</h2>
              <button
                onClick={() => setShowUpgradeModal(false)}
                className="text-gray-400 hover:text-white text-2xl"
              >
                ×
              </button>
            </div>

            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
              {tierInfo.upgrade_options.map((option) => (
                <div
                  key={option.target_tier}
                  className="border border-gray-700 rounded-lg p-6 hover:border-cyan-500 transition-all"
                >
                  <div className="flex items-center justify-between mb-4">
                    <h3 className="text-xl font-semibold text-white capitalize">
                      {option.target_tier}
                    </h3>
                    <div className="text-right">
                      <div className="text-2xl font-bold text-cyan-400">
                        ${option.price_per_month}
                      </div>
                      <div className="text-xs text-gray-500">per endpoint/month</div>
                    </div>
                  </div>

                  <p className="text-sm text-gray-400 mb-4">{option.description}</p>

                  <ul className="space-y-2 mb-6">
                    {option.features.map((feature, idx) => (
                      <li key={idx} className="text-sm text-gray-300 flex items-start gap-2">
                        <span className="text-green-400">✓</span>
                        <span>{feature}</span>
                      </li>
                    ))}
                  </ul>

                  <button
                    onClick={() => handleUpgrade(option.target_tier)}
                    className="w-full py-2 bg-gradient-to-r from-cyan-500 to-blue-500 hover:from-cyan-600 hover:to-blue-600 text-white rounded-lg transition-all"
                  >
                    Upgrade to {option.target_tier}
                  </button>
                </div>
              ))}
            </div>

            <div className="mt-6 p-4 bg-gray-800 rounded-lg">
              <p className="text-sm text-gray-400">
                <strong className="text-white">Note:</strong> Upgrades take effect immediately.
                You'll be charged prorated for the current billing period. Cancel anytime.
              </p>
            </div>
          </div>
        </div>
      )}
    </>
  )
}
