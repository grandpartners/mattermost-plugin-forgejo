// Copyright (c) 2015-present Mattermost, Inc. All Rights Reserved.
// See LICENSE.txt for license information.

import React from 'react';
import PropTypes from 'prop-types';

export default class Setting extends React.PureComponent {
    static propTypes = {
        inputId: PropTypes.string,
        label: PropTypes.node,
        children: PropTypes.node.isRequired,
        helpText: PropTypes.node,
        required: PropTypes.bool,
        hideRequiredStar: PropTypes.bool,
    };

    render() {
        const {
            children,
            helpText,
            inputId,
            label,
            required,
            hideRequiredStar,
        } = this.props;

        const showLabelRow = label || (required && !hideRequiredStar);

        return (
            <div
                className='form-group less'
                style={{marginBottom: '8px'}}
            >
                {showLabelRow && (
                    <div
                        style={{
                            display: 'flex',
                            alignItems: 'center',
                            gap: '3px',
                            marginBottom: '4px',
                            position: 'relative',
                        }}
                    >
                        {label && (
                            <label
                                className='control-label'
                                htmlFor={inputId}
                                style={{marginBottom: 0}}
                            >
                                {label}
                            </label>)
                        }
                        {required && !hideRequiredStar && (
                            <span
                                className='error-text'
                                style={{position: 'relative', top: '1px'}}
                            >
                                {'*'}
                            </span>
                        )
                        }
                    </div>
                )}
                <div>
                    {children}
                    <div
                        className='help-text'
                        style={{margin: '0px'}}
                    >
                        {helpText}
                    </div>
                </div>
            </div>
        );
    }
}
