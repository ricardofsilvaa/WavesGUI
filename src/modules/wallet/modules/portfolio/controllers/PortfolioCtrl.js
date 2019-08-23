(function () {
    'use strict';

    const { get } = require('ts-utils');

    const { splitEvery, flatten } = require('ramda');

    const searchByNameAndId = ($scope, key, list) => {
        const query = $scope[key];
        if (!query) {
            return list;
        }

        return list.filter((item) => {
            const name = get({ item }, 'item.asset.name');
            const id = get({ item }, 'item.asset.id');
            return String(name).toLowerCase().indexOf(query.toLowerCase()) !== -1 || String(id) === query;
        });
    };

    const ds = require('data-service');
    const { BigNumber } = require('@waves/bignumber');

    /**
     * @param {Base} Base
     * @param {$rootScope.Scope} $scope
     * @param {Waves} waves
     * @param {app.utils} utils
     * @param {ModalManager} modalManager
     * @param {User} user
     * @param {EventManager} eventManager
     * @param {GatewayService} gatewayService
     * @param {$state} $state
     * @param {STService} stService
     * @param {VisibleService} visibleService
     * @param {BalanceWatcher} balanceWatcher
     * @return {PortfolioCtrl}
     */
    const controller = function (Base, $scope, waves, utils, modalManager, user,
                                 eventManager, gatewayService, $state,
                                 stService, visibleService, balanceWatcher) {

        class PortfolioCtrl extends Base {

            constructor() {
                super($scope);
                /**
                 * @type {string}
                 */
                this.mirrorId = user.getSetting('baseAssetId');
                /**
                 * @type {Asset}
                 */
                this.mirror = null;
                /**
                 * @type {string[]}
                 */
                this.pinned = [];
                /**
                 * @type {string}
                 */
                this.address = user.address;
                /**
                 * @type {Array<string>}
                 */
                this.spam = [];
                /**
                 * @type {PortfolioCtrl.IBalances}
                 */
                this.details = null;
                /**
                 * @type {Array<PortfolioCtrl.IPortfolioBalanceDetails>}
                 */
                this.balanceList = [];
                /**
                 * @type {string}
                 */
                this.filter = null;
                /**
                 * @type {Moment}
                 */
                this.chartStartDate = utils.moment().add().day(-7);
                /**
                 * @type {boolean}
                 */
                this.pending = true;
                /**
                 * @type {boolean}
                 */
                this.dontShowSpam = user.getSetting('dontShowSpam');

                waves.node.assets.getAsset(this.mirrorId)
                    .then((mirror) => {
                        this.mirror = mirror;
                        /**
                         * @type {Array<SmartTable.IHeaderInfo>}
                         */
                        this.tableHeaders = [
                            {
                                id: 'name',
                                title: { literal: 'list.name' },
                                valuePath: 'item.asset.name',
                                sort: true,
                                search: searchByNameAndId,
                                placeholder: 'portfolio.filter'
                            },
                            {
                                id: 'balance',
                                title: { literal: 'list.balance' },
                                valuePath: 'item.available',
                                sort: true
                            },
                            {
                                id: 'inOrders',
                                title: { literal: 'list.inOrders' },
                                valuePath: 'item.inOrders',
                                sort: true
                            },
                            {
                                id: 'mirror',
                                title: { literal: 'list.mirror', params: { currency: mirror.displayName } },
                                valuePath: 'item.amount',
                                sort: true
                            },
                            {
                                id: 'rate',
                                title: { literal: 'list.rate', params: { currency: mirror.displayName } },
                                valuePath: 'item.rate',
                                sort: true
                            },
                            {
                                id: 'change24',
                                title: { literal: 'list.change' },
                                valuePath: 'item.change24',
                                sort: true
                            },
                            {
                                id: 'controls'
                            }
                        ];

                        $scope.$digest();
                    });

                this.syncSettings({
                    pinned: 'pinnedAssetIdList',
                    spam: 'wallet.portfolio.spam',
                    filter: 'wallet.portfolio.filter',
                    dontShowSpam: 'dontShowSpam'
                });

                balanceWatcher.ready
                    .then(() => {
                        const onChange = () => {
                            this._updateBalances();
                            visibleService.updateSort();
                        };

                        this.receive(balanceWatcher.change, onChange);
                        this.receive(utils.observe(user, 'scam'), onChange);
                        this.observe(['pinned', 'spam', 'dontShowSpam'], onChange);

                        this._updateBalances();
                    });

                balanceWatcher.ready.then(() => {
                    this.pending = false;
                    this.observe('details', this._onChangeDetails);
                    this.observe('filter', this._onChangeDetails);

                    // this._onChangeDetails();
                    utils.safeApply($scope);
                });

                this.receive(stService.sort, () => {
                    visibleService.updateSort();
                });
            }

            /**
             * @param {Asset} asset
             */
            showAsset(asset) {
                modalManager.showAssetInfo(asset);
            }

            /**
             * @param {Asset} asset
             */
            showSend(asset) {
                return modalManager.showSendAsset({ assetId: asset && asset.id });
            }

            /**
             * @param {Asset} asset
             */
            showReceivePopup(asset) {
                return modalManager.showReceiveModal(asset);
            }

            /**
             * @param {Asset} asset
             */
            showDeposit(asset) {
                return modalManager.showDepositAsset(user, asset);
            }

            /**
             * @param {Asset} asset
             */
            showSepa(asset) {
                return modalManager.showSepaAsset(user, asset);
            }

            showBurn(assetId) {
                return modalManager.showBurnModal(assetId);
            }

            showReissue(assetId) {
                return modalManager.showReissueModal(assetId);
            }

            canShowDex(balance) {
                return balance.isPinned ||
                    balance.asset.isMyAsset ||
                    balance.asset.id === WavesApp.defaultAssets.WAVES ||
                    gatewayService.getPurchasableWithCards()[balance.asset.id] ||
                    gatewayService.getCryptocurrencies()[balance.asset.id] ||
                    gatewayService.getFiats()[balance.asset.id];
            }

            /**
             * @param {Asset} asset
             */
            openDex(asset) {
                $state.go('main.dex', this.getSrefParams(asset));
            }

            /**
             * @param {Asset} asset
             */
            getSrefParams(asset) {
                utils.openDex(asset.id);
            }

            /**
             * @param {Asset} asset
             * @param {boolean} [state]
             */
            togglePin(asset, state) {
                user.togglePinAsset(asset.id, state);
                this.poll.restart();
            }

            /**
             * @param {Asset} asset
             * @param {boolean} [state]
             */
            toggleSpam(asset, state) {
                user.toggleSpamAsset(asset.id, state);
                this.poll.restart();
            }

            isDepositSupported(asset) {
                const isWaves = asset.id === WavesApp.defaultAssets.WAVES;

                return gatewayService.hasSupportOf(asset, 'deposit') || isWaves;
            }

            isSepaSupported(asset) {
                return gatewayService.hasSupportOf(asset, 'sepa');
            }

            /**
             * @private
             */
            _onChangeDetails() {
                const details = this.details;
                let balanceList;

                switch (this.filter) {
                    case 'active':
                        balanceList = details.active.slice();
                        break;
                    case 'pinned':
                        balanceList = details.pinned.slice();
                        break;
                    case 'spam':
                        balanceList = details.spam.slice();
                        break;
                    case 'my':
                        balanceList = details.my.slice();
                        break;
                    case 'verified':
                        balanceList = details.verified.slice();
                        break;
                    default:
                        throw new Error('Wrong filter name!');
                }

                this.balanceList = balanceList;
            }

            _addRating(balanceList) {
                return Promise.all(splitEvery(25, balanceList).map(block => {
                    return ds.api.rating.getAssetsRating(block.map(balanceItem => balanceItem.asset.id));
                })).then(list => {
                    const listHash = utils.toHash(flatten(list), 'assetId');
                    return balanceList.map(balanceItem => {
                        balanceItem.rating = listHash[balanceItem.asset.id] ?
                            listHash[balanceItem.asset.id].rating :
                            null;
                        return balanceItem;
                    });
                })
                    .catch(() => {
                        return balanceList;
                    });
            }

            /**
             * @private
             */
            _updateBalances() {
                const balanceList = balanceWatcher.getFullBalanceList();
                const baseAssetId = user.getSetting('baseAssetId');
                const assetList = balanceList.map(balance => balance.asset);
                const lastDayDate = utils.moment().add().day(-1).format('YYYY-MM-DD');

                Promise.all([
                    this._addRating(balanceList),
                    ...splitEvery(20, assetList).map(list => waves.utils.getRateList(list, baseAssetId)),
                    ...splitEvery(20, assetList).map(list => waves.utils.getRateList(list, baseAssetId, lastDayDate))
                    // ...waves.utils.getRateListPost(assetList, baseAssetId)
                ]).then(([balanceListWithRating, ...rateData]) => {
                    const currentRateData = rateData.filter((data, i) => i < rateData.length / 2);
                    const lastRateData = rateData.filter((data, i) => i >= rateData.length / 2);

                    const flattenCurrentRateData = flatten(currentRateData.map(item => item.data));
                    const currentRates = flattenCurrentRateData.map(item => new BigNumber(item.data.current));

                    const flattenLastRateData = flatten(lastRateData.map(item => item.data));
                    const lastRates = flattenLastRateData.map(item => new BigNumber(item.data.current));

                    this.details = balanceListWithRating
                        .map((item, idx) => {
                            const isPinned = this._isPinned(item.asset.id);
                            const isSpam = this._isSpam(item.asset.id);
                            const isOnScamList = user.scam[item.asset.id];
                            return {
                                available: item.available,
                                asset: item.asset,
                                inOrders: item.inOrders,
                                isPinned,
                                isSpam,
                                isOnScamList,
                                rating: item.rating || null,
                                minSponsoredAssetFee: item.asset.minSponsoredAssetFee,
                                sponsorBalance: item.asset.sponsorBalance,
                                leasedOut: item.leasedOut,
                                change24: this._getChange24(currentRates[idx], lastRates[idx]),
                                rate: currentRates[idx],
                                amount: (new BigNumber(currentRates[idx].roundTo(2))).mul(item.available.getTokens())
                            };
                        })
                        .reduce((acc, item) => {
                            const oracleData = ds.dataManager.getOraclesAssetData(item.asset.id);
                            const spam = item.isOnScamList || item.isSpam;

                            if (oracleData && oracleData.status > 0) {
                                acc.verified.push(item);
                            }

                            if (spam) {
                                if (!this.dontShowSpam) {
                                    if (item.asset.sender === user.address) {
                                        acc.my.push(item);
                                    }
                                    acc.spam.push(item);
                                    acc.active.push(item);
                                }
                            } else {
                                if (item.asset.sender === user.address) {
                                    acc.my.push(item);
                                }
                                acc.active.push(item);
                            }

                            return acc;
                        }, { spam: [], my: [], active: [], verified: [] });


                    utils.safeApply($scope);
                });
            }

            /**
             * @param assetId
             * @return {boolean}
             * @private
             */
            _isPinned(assetId) {
                return this.pinned.includes(assetId);
            }

            /**
             * @param assetId
             * @return {boolean}
             * @private
             */
            _isSpam(assetId) {
                return this.spam.includes(assetId);
            }

            /**
             * @param {BigNumber} last
             * @param {BigNumber} current
             * @return {BigNumber}
             * @private
             */
            _getChange24(currentRate, lastRate) {
                if (lastRate.isZero()) {
                    return new BigNumber(0);
                }
                return currentRate.sub(lastRate).div(lastRate).mul(100).roundTo(2);
            }

        }

        return new PortfolioCtrl();
    };

    controller.$inject = [
        'Base',
        '$scope',
        'waves',
        'utils',
        'modalManager',
        'user',
        'eventManager',
        'gatewayService',
        '$state',
        'stService',
        'visibleService',
        'balanceWatcher'
    ];

    angular.module('app.wallet.portfolio')
        .controller('PortfolioCtrl', controller);
})();

/**
 * @name PortfolioCtrl
 */

/**
 * @typedef {object} PortfolioCtrl#IPortfolioBalanceDetails
 * @property {boolean} isPinned
 * @property {boolean} isSpam
 * @property {boolean} isOnScamList
 * @property {Asset} asset
 * @property {Money} available
 * @property {Money} inOrders
 * @property {Money|void} minSponsoredAssetFee
 * @property {Money|void} sponsorBalance
 */

/**
 * @typedef {object} PortfolioCtrl#IBalances
 * @property {Array<PortfolioCtrl.IPortfolioBalanceDetails>} active
 * @property {Array<PortfolioCtrl.IPortfolioBalanceDetails>} pinned // TODO when available assets store
 * @property {Array<PortfolioCtrl.IPortfolioBalanceDetails>} spam
 * @property {Array<PortfolioCtrl.IPortfolioBalanceDetails>} my
 * @property {Array<PortfolioCtrl.IPortfolioBalanceDetails>} verified
 */
