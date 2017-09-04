(function () {
    'use strict';

    const controller = function ($element, $attrs, i18n) {
        return {
            listener: null,
            $postLink() {
                const isAttribute = !!$attrs.wI18n;
                const ns = i18n.getNs($element);

                let literal;

                if (isAttribute) {
                    literal = $attrs.wI18n;
                } else {
                    literal = $element.text();
                }

                const listener = function () {
                    $element.html(i18n.translate(literal, ns));
                };
                listener();
                this.listener = listener;
                i18next.on('languageChanged', listener);
            },
            $onDestroy() {
                i18next.off('languageChanged', this.listener);
            }
        };
    };

    controller.$inject = ['$element', '$attrs', 'i18n'];

    angular.module('app').directive('wI18n', () => {
        return {
            restrict: 'AE',
            controller: controller,
            transclude: true,
            template: function ($element) {
                if ($element.get(0).tagName === 'W-I18N') {
                    return '<span ng-transclude></span>';
                }
            }
        };
    });
})();
